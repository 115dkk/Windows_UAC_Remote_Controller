// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.background

import android.app.Notification
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.BroadcastReceiver
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.SystemClock
import android.os.UserManager
import androidx.lifecycle.Lifecycle
import dev.dkk115.uacremote.ControllerApplication
import dev.dkk115.uacremote.MainActivity
import java.io.FileDescriptor
import java.io.PrintWriter

/** Foreground lifetime only; no socket, approval action, key or CE store at boot. */
class ControllerForegroundService : Service() {
    private val ownerToken = Any()
    private var promoted = false
    private var attached = false
    private var activatedGeneration: Long? = null
    private var retiring = false
    private var destroyed = false
    private var unlockReceiverRegistered = false
    private var unlockRegistrationAttempted = false
    private var activationWaitStartId: Int? = null
    private val main = Handler(Looper.getMainLooper())
    private val connectivityToken = Any()
    private var connectivityTickPosted = false
    private val connectivityTick = object : Runnable {
        override fun run() {
            connectivityTickPosted = false
            val owner = application as? ControllerApplication
            if (!connectionMaintenanceReady(owner)) { stopConnectivityTick(); return }
            owner?.policyActor?.maintainConnections()
            scheduleConnectivityTick()
        }
    }
    private val unlockReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            if (!destroyed && intent.action == Intent.ACTION_USER_UNLOCKED) refreshAfterUnlock()
        }
    }

    override fun onCreate() {
        super.onCreate()
        BootDiagnostics.record(BootDiagnosticRecord(BootDiagnosticStage.SERVICE_CREATE))
        val owner = application as? ControllerApplication
        // Track the real Service instance from construction, before promotion
        // or onStartCommand. Stop/start cannot mistake this attached object for
        // an absent service while its onDestroy is still outstanding.
        if (owner == null || !owner.attachControllerService(ownerToken, ::showState)) {
            BootDiagnostics.record(BootDiagnosticRecord(BootDiagnosticStage.ATTACHMENT_REJECTED))
            stopSelf()
            return
        }
        attached = true
        val unlock = observeUnlock(this)
        val initial = when (unlock) {
            UserUnlockObservation.LOCKED -> ControllerServiceState.WAITING_FOR_UNLOCK
            UserUnlockObservation.UNLOCKED -> ControllerServiceState.PREPARING
            UserUnlockObservation.UNAVAILABLE -> ControllerServiceState.UNAVAILABLE
        }
        try {
            ControllerStatusNotificationRenderer(this).ensureChannel()
            // Promote promptly BEFORE any Rust/CE/key-owner construction.
            startForeground(ControllerStatusNotificationRenderer.NOTIFICATION_ID, notification(initial), ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE)
            promoted = true
            BootDiagnostics.record(BootDiagnosticRecord(BootDiagnosticStage.PROMOTION_SUCCEEDED, unlock = unlock))
        } catch (failure: Exception) {
            BootDiagnostics.record(BootDiagnosticRecord(BootDiagnosticStage.PROMOTION_FAILED,
                unlock = unlock, failure = BootDiagnostics.failureCategory(failure)))
            owner.controllerServiceStartRejected(token = ownerToken)
            stopSelf()
            return
        }
        registerForUnlockIfNeeded()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        BootDiagnostics.record(BootDiagnosticRecord(BootDiagnosticStage.START_COMMAND,
            sticky = intent == null, attached = attached, promoted = promoted))
        val owner = application as? ControllerApplication
        if (!promoted || owner == null || !attached) {
            stopConnectivityTick()
            stopSelfResult(startId)
            return START_NOT_STICKY
        }
        val supplied = if (intent == null) null else try {
            intent.getLongExtra(EXTRA_GENERATION, 0L).takeIf { it > 0 }
        } catch (_: Exception) { null }
        activationWaitStartId = null // A newer callback owns its own continuation.
        if (retiring || (intent != null && intent.action != ACTION_START && intent.action != ACTION_EXPLICIT_START)) {
            return rejectStart(owner, supplied, startId)
        }
        val sticky = intent == null
        val explicit = intent?.action == ACTION_EXPLICIT_START
        if (owner.controllerBootActivationState() == BootActivationState.LOADING) {
            // A real sticky Service is already foreground-promoted. Wait for DE
            // observation without touching CE or constructing the Rust actor.
            val started = SystemClock.elapsedRealtime()
            activationWaitStartId = startId
            owner.whenControllerBootActivationObserved { available ->
                if (destroyed || retiring || !attached || !promoted || activationWaitStartId != startId) return@whenControllerBootActivationObserved
                activationWaitStartId = null
                if (!available || BootServicePolicy.serviceCommandExpired(started, SystemClock.elapsedRealtime())) rejectStart(owner, supplied, startId)
                else acceptStart(owner, supplied, sticky, explicit, startId)
            }
            return START_STICKY
        }
        return acceptStart(owner, supplied, sticky, explicit, startId)
    }

    private fun acceptStart(owner: ControllerApplication, supplied: Long?, sticky: Boolean, explicit: Boolean, startId: Int): Int {
        val component = componentState(this)
        if (!BootServicePolicy.bootEnabled(component) || !owner.controllerBootActivationEnabled()) {
            BootDiagnostics.record(BootDiagnosticRecord(BootDiagnosticStage.COMPONENT_REJECTED,
                component = component, activation = owner.controllerBootActivationState()))
            owner.controllerServiceStartRejected(activatedGeneration, ownerToken)
            retiring = true
            stopConnectivityTick()
            stopSelfResult(startId)
            return START_NOT_STICKY
        }
        // Null is accepted only from the actual framework sticky callback, with
        // enabled boot/current token and no stop/cleanup/uncertain construction.
        // The plugin cannot supply null/stale intent data through its no-args API.
        val generation = if (sticky) owner.stickyControllerServiceGeneration(ownerToken) else supplied
        if (generation == null) return rejectStart(owner, supplied, startId)
        registerForUnlockIfNeeded()
        if (!owner.startControllerServiceOwner(ownerToken, explicit, generation)) {
            return rejectStart(owner, generation, startId)
        }
        activatedGeneration = generation
        scheduleConnectivityTick()
        BootDiagnostics.record(BootDiagnosticRecord(BootDiagnosticStage.GENERATION_ACCEPTED,
            component = component, sticky = sticky, generationPresent = true, admitted = true,
            activation = owner.controllerBootActivationState()))
        if (observeUnlock(this) == UserUnlockObservation.UNLOCKED) unregisterUnlockReceiver()
        return START_STICKY
    }

    private fun rejectStart(owner: ControllerApplication, generation: Long?, startId: Int): Int {
        // A stale start must not stop a newer already-active instance. An old
        // unactivated object is retired instead of hosting a replacement actor.
        val current = owner.isCurrentControllerServiceGeneration(ownerToken, activatedGeneration)
        BootDiagnostics.record(BootDiagnosticRecord(BootDiagnosticStage.GENERATION_REJECTED,
            generationPresent = generation != null, admitted = false, keptCurrent = current))
        if (current) return START_STICKY
        retiring = true
        stopConnectivityTick()
        owner.controllerServiceStartRejected(generation, ownerToken)
        stopSelfResult(startId)
        return START_NOT_STICKY
    }

    private fun registerForUnlockIfNeeded() {
        if (unlockRegistrationAttempted || observeUnlock(this) == UserUnlockObservation.UNLOCKED) return
        unlockRegistrationAttempted = true
        try {
            val filter = IntentFilter(Intent.ACTION_USER_UNLOCKED)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                registerReceiver(unlockReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
            } else {
                registerReceiver(unlockReceiver, filter)
            }
            unlockReceiverRegistered = true
        } catch (failure: Exception) {
            BootDiagnostics.record(BootDiagnosticRecord(BootDiagnosticStage.UNLOCK_RECEIVER_FAILED,
                failure = BootDiagnostics.failureCategory(failure)))
            showState(ControllerServiceState.UNAVAILABLE)
        }
        // Register-then-check closes the unlock-between-check-and-registration race.
        if (observeUnlock(this) == UserUnlockObservation.UNLOCKED) refreshAfterUnlock()
    }

    private fun refreshAfterUnlock() {
        BootDiagnostics.record(BootDiagnosticRecord(BootDiagnosticStage.UNLOCK_REFRESH,
            generationPresent = activatedGeneration != null, attached = attached, promoted = promoted))
        if (!promoted || destroyed || !attached) return
        val generation = activatedGeneration ?: return
        // Broadcast contents never establish storage availability themselves.
        (application as? ControllerApplication)?.startControllerServiceOwner(ownerToken, false, generation)
        if (observeUnlock(this) == UserUnlockObservation.UNLOCKED) unregisterUnlockReceiver()
    }

    private fun unregisterUnlockReceiver() {
        if (!unlockReceiverRegistered) return
        try { unregisterReceiver(unlockReceiver); unlockReceiverRegistered = false }
        catch (_: Exception) { /* retain the registration obligation until destroy */ }
    }

    private fun connectionMaintenanceReady(owner: ControllerApplication?): Boolean =
        promoted && attached && !retiring && !destroyed && owner != null &&
            owner.isCurrentControllerServiceGeneration(ownerToken, activatedGeneration) &&
            owner.policyActor?.lifecyclePhase() == PolicyOwnerPhase.READY

    private fun scheduleConnectivityTick() {
        if (!connectionMaintenanceReady(application as? ControllerApplication)) { stopConnectivityTick(); return }
        if (!connectivityTickPosted) {
            connectivityTickPosted = main.postDelayed(connectivityTick, connectivityToken, CONNECTION_TICK_MILLIS)
        }
    }

    private fun stopConnectivityTick() {
        main.removeCallbacksAndMessages(connectivityToken)
        connectivityTickPosted = false
    }

    private fun showState(state: ControllerServiceState) {
        if (state == ControllerServiceState.LOCAL_SETTINGS_READY) scheduleConnectivityTick() else stopConnectivityTick()
        if (!promoted || destroyed) return
        try {
            val manager = getSystemService(NotificationManager::class.java) ?: throw IllegalStateException()
            manager.notify(ControllerStatusNotificationRenderer.NOTIFICATION_ID, notification(state))
        } catch (failure: Exception) {
            BootDiagnostics.record(BootDiagnosticRecord(BootDiagnosticStage.NOTIFICATION_FAILED,
                failure = BootDiagnostics.failureCategory(failure)))
            // No invisible replacement/background worker is started on failure.
            retiring = true
            stopConnectivityTick()
            (application as? ControllerApplication)?.controllerServiceStartRejected(activatedGeneration, ownerToken)
            stopSelf()
        }
    }

    private fun notification(state: ControllerServiceState): Notification {
        val open = Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP)
        val pending = PendingIntent.getActivity(this, ControllerStatusNotificationRenderer.NOTIFICATION_ID, open, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        return ControllerStatusNotificationRenderer(this).build(state, pending)
    }

    override fun onBind(intent: Intent?): IBinder? = null

    /** Android's existing dumpsys/DUMP-permission path only. ActivityThread
     * dispatches Service.dump on main; a different thread gets no guessed state.
     * Ignore all caller arguments. Fixed bounded fields, no body/key/alias/paths,
     * no Activity, native owner initialization or synchronous worker request. */
    override fun dump(fd: FileDescriptor, writer: PrintWriter, args: Array<out String>?) {
        if (Looper.myLooper() != Looper.getMainLooper()) {
            writer.println("UAC_LIFECYCLE_UNAVAILABLE_V1")
            return
        }
        val owner = (application as? ControllerApplication)?.controllerLifecycleDiagnosticLines()
        if (owner == null) {
            writer.println("UAC_LIFECYCLE_UNAVAILABLE_V1")
            return
        }
        writer.println("UAC_LIFECYCLE_BEGIN_V1")
        writer.println("promoted=$promoted")
        writer.println("attached=$attached")
        writer.println("destroyed=$destroyed")
        writer.println("retiring=$retiring")
        writer.println("user_unlock=${observeUnlock(this).name}")
        writer.println("boot_component=${componentState(this).name}")
        for (line in owner) writer.println(line)
        writer.println("UAC_LIFECYCLE_END_V1")
    }

    override fun onDestroy() {
        BootDiagnostics.record(BootDiagnosticRecord(BootDiagnosticStage.SERVICE_DESTROY,
            generationPresent = activatedGeneration != null, attached = attached, promoted = promoted))
        destroyed = true
        stopConnectivityTick()
        activationWaitStartId = null
        unregisterUnlockReceiver()
        if (attached) (application as? ControllerApplication)?.detachControllerService(ownerToken, activatedGeneration)
        attached = false
        if (promoted) stopForeground(STOP_FOREGROUND_REMOVE)
        promoted = false
        super.onDestroy()
    }

    companion object {
        private const val CONNECTION_TICK_MILLIS = 15_000L
        private const val ACTION_START = "dev.dkk115.uacremote.service.START"
        private const val ACTION_EXPLICIT_START = "dev.dkk115.uacremote.service.EXPLICIT_START"
        private const val EXTRA_GENERATION = "dev.dkk115.uacremote.service.NATIVE_GENERATION"

        internal fun observeUnlock(context: Context): UserUnlockObservation = try {
            when (context.getSystemService(UserManager::class.java)?.isUserUnlocked) {
                true -> UserUnlockObservation.UNLOCKED
                false -> UserUnlockObservation.LOCKED
                null -> UserUnlockObservation.UNAVAILABLE
            }
        } catch (_: Exception) { UserUnlockObservation.UNAVAILABLE }

        internal fun componentState(context: Context): BootComponentState = componentState(context, ControllerBootWakeReceiver::class.java)

        /** Filterless old component is observed only for one-time migration. */
        internal fun legacyComponentState(context: Context): BootComponentState = componentState(context, ControllerBootReceiver::class.java)

        private fun componentState(context: Context, type: Class<*>): BootComponentState = try {
            when (context.packageManager.getComponentEnabledSetting(ComponentName(context, type))) {
                PackageManager.COMPONENT_ENABLED_STATE_DEFAULT -> BootComponentState.DEFAULT
                PackageManager.COMPONENT_ENABLED_STATE_ENABLED -> BootComponentState.ENABLED
                PackageManager.COMPONENT_ENABLED_STATE_DISABLED, PackageManager.COMPONENT_ENABLED_STATE_DISABLED_USER,
                PackageManager.COMPONENT_ENABLED_STATE_DISABLED_UNTIL_USED -> BootComponentState.DISABLED
                else -> BootComponentState.UNAVAILABLE
            }
        } catch (_: Exception) { BootComponentState.UNAVAILABLE }

        /** Automatic paths only wait/read; they never overwrite OFF/unknown. */
        internal fun startIfEnabled(context: Context, callback: (ServiceControlResult) -> Unit = {}) {
            if (Looper.myLooper() != Looper.getMainLooper()) { callback(ServiceControlResult.UNAVAILABLE); return }
            val owner = context.applicationContext as? ControllerApplication
            if (owner == null) { callback(ServiceControlResult.UNAVAILABLE); return }
            val started = SystemClock.elapsedRealtime()
            owner.whenControllerBootActivationObserved { available ->
                val visible = context !is MainActivity || (!context.isDestroyed && !context.isFinishing &&
                    context.lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED))
                callback(if (!available || !visible || BootServicePolicy.serviceCommandExpired(started, SystemClock.elapsedRealtime())) ServiceControlResult.UNAVAILABLE
                    else requestStart(context, false, started))
            }
        }

        /** Actual native start intent only; not the Activity's automatic hook. */
        internal fun startExplicit(context: Context, started: Long = SystemClock.elapsedRealtime(), callback: (ServiceControlResult) -> Unit) {
            if (Looper.myLooper() != Looper.getMainLooper()) { callback(ServiceControlResult.UNAVAILABLE); return }
            val activity = context as? MainActivity
            val owner = activity?.application as? ControllerApplication
            if (activity == null || owner == null) { callback(ServiceControlResult.NOT_ALLOWED); return }
            owner.startControllerServiceExplicit(activity, started, callback)
        }

        internal fun startAfterRegistration(activity: MainActivity, started: Long): ServiceControlResult = requestStart(activity, true, started)

        private fun requestStart(context: Context, explicit: Boolean, started: Long): ServiceControlResult {
            if (Looper.myLooper() != Looper.getMainLooper()) return ServiceControlResult.UNAVAILABLE
            if (BootServicePolicy.serviceCommandExpired(started, SystemClock.elapsedRealtime())) return ServiceControlResult.UNAVAILABLE
            val owner = context.applicationContext as? ControllerApplication ?: return ServiceControlResult.UNAVAILABLE
            if (explicit) {
                val activity = context as? MainActivity ?: return ServiceControlResult.NOT_ALLOWED
                if (!owner.isCurrentForegroundControllerHost(activity)) return ServiceControlResult.NOT_ALLOWED
                val observation = owner.observeControllerService(activity)
                if (observation.bootEnabled == null) return ServiceControlResult.UNAVAILABLE
                if (!observation.canStart) return ServiceControlResult.NOT_ALLOWED
            } else if (!owner.canRequestAutomaticServiceStart()) return ServiceControlResult.NOT_ALLOWED
            val state = componentState(context)
            if (!BootServicePolicy.bootEnabled(state) || !owner.controllerBootActivationEnabled()) return ServiceControlResult.DISABLED
            if (BootServicePolicy.serviceCommandExpired(started, SystemClock.elapsedRealtime())) return ServiceControlResult.UNAVAILABLE
            val generation = owner.controllerServiceStartRequested() ?: return ServiceControlResult.UNAVAILABLE
            return try {
                val intent = Intent(context, ControllerForegroundService::class.java)
                    .setAction(if (explicit) ACTION_EXPLICIT_START else ACTION_START)
                    .putExtra(EXTRA_GENERATION, generation)
                if (BootServicePolicy.serviceCommandExpired(started, SystemClock.elapsedRealtime())) throw IllegalStateException()
                if (context.startForegroundService(intent) == null) throw IllegalStateException()
                BootDiagnostics.record(BootDiagnosticRecord(BootDiagnosticStage.START_REQUESTED,
                    component = state, result = ServiceControlResult.REQUESTED))
                ServiceControlResult.REQUESTED
            } catch (failure: Exception) {
                BootDiagnostics.record(BootDiagnosticRecord(BootDiagnosticStage.START_REQUEST_FAILED,
                    component = state, failure = BootDiagnostics.failureCategory(failure)))
                // OS denial/force-stop/OEM limits are not bypassed or loop-retried.
                owner.controllerServiceStartRejected(generation)
                ServiceControlResult.UNAVAILABLE
            }
        }

        internal fun stopExplicit(context: Context, started: Long = SystemClock.elapsedRealtime(), callback: (ServiceControlResult) -> Unit) {
            if (Looper.myLooper() != Looper.getMainLooper()) { callback(ServiceControlResult.UNAVAILABLE); return }
            val activity = context as? MainActivity
            val owner = activity?.application as? ControllerApplication
            if (activity == null || owner == null) { callback(ServiceControlResult.NOT_ALLOWED); return }
            owner.stopControllerServiceExplicit(activity, started, callback)
        }
    }
}
