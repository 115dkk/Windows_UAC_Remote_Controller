// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.background

import android.app.Notification
import android.app.NotificationChannel
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
import android.os.IBinder
import android.os.Looper
import android.os.UserManager
import dev.dkk115.uacremote.ControllerApplication
import dev.dkk115.uacremote.MainActivity
import dev.dkk115.uacremote.R

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
    private val unlockReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            if (!destroyed && intent.action == Intent.ACTION_USER_UNLOCKED) refreshAfterUnlock()
        }
    }

    override fun onCreate() {
        super.onCreate()
        val owner = application as? ControllerApplication
        // Track the real Service instance from construction, before promotion
        // or onStartCommand. Stop/start cannot mistake this attached object for
        // an absent service while its onDestroy is still outstanding.
        if (owner == null || !owner.attachControllerService(ownerToken, ::showState)) {
            stopSelf()
            return
        }
        attached = true
        val initial = when (observeUnlock(this)) {
            UserUnlockObservation.LOCKED -> ControllerServiceState.WAITING_FOR_UNLOCK
            UserUnlockObservation.UNLOCKED -> ControllerServiceState.PREPARING
            UserUnlockObservation.UNAVAILABLE -> ControllerServiceState.UNAVAILABLE
        }
        try {
            val manager = getSystemService(NotificationManager::class.java) ?: throw IllegalStateException()
            val channel = NotificationChannel(CHANNEL_ID, getString(R.string.controller_service_channel), NotificationManager.IMPORTANCE_LOW)
            channel.description = getString(R.string.controller_service_channel_description)
            channel.setSound(null, null)
            channel.enableVibration(false)
            channel.setShowBadge(false)
            manager.createNotificationChannel(channel)
            // Promote promptly BEFORE any Rust/CE/key-owner construction.
            startForeground(NOTIFICATION_ID, notification(initial), ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE)
            promoted = true
        } catch (_: Exception) {
            owner.controllerServiceStartRejected(token = ownerToken)
            stopSelf()
            return
        }
        registerForUnlockIfNeeded()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val owner = application as? ControllerApplication
        if (!promoted || owner == null || !attached) {
            stopSelfResult(startId)
            return START_NOT_STICKY
        }
        if (!BootServicePolicy.bootEnabled(componentState(this))) {
            owner.controllerServiceStartRejected(activatedGeneration, ownerToken)
            retiring = true
            stopSelfResult(startId)
            return START_NOT_STICKY
        }
        val supplied = if (intent == null) null else try {
            intent.getLongExtra(EXTRA_GENERATION, 0L).takeIf { it > 0 }
        } catch (_: Exception) { null }
        if (retiring || (intent != null && intent.action != ACTION_START && intent.action != ACTION_EXPLICIT_START)) {
            return rejectStart(owner, supplied, startId)
        }
        // Null is accepted only from the actual framework sticky callback, with
        // enabled boot/current token and no stop/cleanup/uncertain construction.
        // The plugin cannot supply null/stale intent data through its no-args API.
        val generation = if (intent == null) owner.stickyControllerServiceGeneration(ownerToken) else supplied
        if (generation == null) return rejectStart(owner, supplied, startId)
        registerForUnlockIfNeeded()
        if (!owner.startControllerServiceOwner(ownerToken, intent?.action == ACTION_EXPLICIT_START, generation)) {
            return rejectStart(owner, generation, startId)
        }
        activatedGeneration = generation
        if (observeUnlock(this) == UserUnlockObservation.UNLOCKED) unregisterUnlockReceiver()
        return START_STICKY
    }

    private fun rejectStart(owner: ControllerApplication, generation: Long?, startId: Int): Int {
        // A stale start must not stop a newer already-active instance. An old
        // unactivated object is retired instead of hosting a replacement actor.
        if (owner.isCurrentControllerServiceGeneration(ownerToken, activatedGeneration)) return START_STICKY
        retiring = true
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
        } catch (_: Exception) {
            showState(ControllerServiceState.UNAVAILABLE)
        }
        // Register-then-check closes the unlock-between-check-and-registration race.
        if (observeUnlock(this) == UserUnlockObservation.UNLOCKED) refreshAfterUnlock()
    }

    private fun refreshAfterUnlock() {
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

    private fun showState(state: ControllerServiceState) {
        if (!promoted || destroyed) return
        try {
            val manager = getSystemService(NotificationManager::class.java) ?: throw IllegalStateException()
            manager.notify(NOTIFICATION_ID, notification(state))
        } catch (_: Exception) {
            // No invisible replacement/background worker is started on failure.
            (application as? ControllerApplication)?.controllerServiceStartRejected(activatedGeneration, ownerToken)
            stopSelf()
        }
    }

    private fun notification(state: ControllerServiceState): Notification {
        val body = when (state) {
            ControllerServiceState.WAITING_FOR_UNLOCK -> R.string.controller_service_locked
            ControllerServiceState.PREPARING -> R.string.controller_service_preparing
            ControllerServiceState.LOCAL_SETTINGS_READY -> R.string.controller_service_ready
            ControllerServiceState.CLEANUP_PENDING -> R.string.controller_service_cleanup
            ControllerServiceState.UNAVAILABLE -> R.string.controller_service_unavailable
            ControllerServiceState.STOPPED -> R.string.controller_service_stopping
        }
        val open = Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP)
        val pending = PendingIntent.getActivity(this, NOTIFICATION_ID, open, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        val builder = Notification.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_controller_service)
            .setContentTitle(getString(R.string.controller_service_title))
            .setContentText(getString(body))
            .setContentIntent(pending)
            .setCategory(Notification.CATEGORY_SERVICE)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setShowWhen(false)
            .setLocalOnly(true)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) builder.setForegroundServiceBehavior(Notification.FOREGROUND_SERVICE_IMMEDIATE)
        return builder.build()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        destroyed = true
        unregisterUnlockReceiver()
        if (attached) (application as? ControllerApplication)?.detachControllerService(ownerToken, activatedGeneration)
        attached = false
        if (promoted) stopForeground(STOP_FOREGROUND_REMOVE)
        promoted = false
        super.onDestroy()
    }

    companion object {
        private const val CHANNEL_ID = "controller_service_status_v1"
        private const val NOTIFICATION_ID = 0x554143
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

        internal fun componentState(context: Context): BootComponentState = try {
            when (context.packageManager.getComponentEnabledSetting(ComponentName(context, ControllerBootReceiver::class.java))) {
                PackageManager.COMPONENT_ENABLED_STATE_DEFAULT -> BootComponentState.DEFAULT
                PackageManager.COMPONENT_ENABLED_STATE_ENABLED -> BootComponentState.ENABLED
                PackageManager.COMPONENT_ENABLED_STATE_DISABLED, PackageManager.COMPONENT_ENABLED_STATE_DISABLED_USER,
                PackageManager.COMPONENT_ENABLED_STATE_DISABLED_UNTIL_USED -> BootComponentState.DISABLED
                else -> BootComponentState.UNAVAILABLE
            }
        } catch (_: Exception) { BootComponentState.UNAVAILABLE }

        /** Automatic visible/boot path: NEVER re-enables a stopped boot component. */
        internal fun startIfEnabled(context: Context): ServiceControlResult = requestStart(context, false)

        /** Actual native start intent only; not the Activity's automatic hook. */
        internal fun startExplicit(context: Context): ServiceControlResult {
            if (Looper.myLooper() != Looper.getMainLooper()) return ServiceControlResult.UNAVAILABLE
            val activity = context as? MainActivity ?: return ServiceControlResult.NOT_ALLOWED
            val owner = activity.application as? ControllerApplication ?: return ServiceControlResult.UNAVAILABLE
            if (!owner.isCurrentForegroundControllerHost(activity)) return ServiceControlResult.NOT_ALLOWED
            val observation = owner.observeControllerService(activity)
            if (observation.bootEnabled == null) return ServiceControlResult.UNAVAILABLE
            if (!observation.canStart) return ServiceControlResult.NOT_ALLOWED
            try {
                context.packageManager.setComponentEnabledSetting(ComponentName(context, ControllerBootReceiver::class.java),
                    PackageManager.COMPONENT_ENABLED_STATE_ENABLED, PackageManager.DONT_KILL_APP)
            } catch (_: Exception) {
                owner.controllerServiceStartRejected()
                return ServiceControlResult.UNAVAILABLE
            }
            if (componentState(context) != BootComponentState.ENABLED) {
                owner.controllerServiceStartRejected()
                return ServiceControlResult.UNAVAILABLE
            }
            val result = requestStart(context, true)
            // Persistent enable may already have succeeded before a later
            // eligibility change. Do not claim an untouched/not-allowed action.
            return if (result == ServiceControlResult.NOT_ALLOWED || result == ServiceControlResult.DISABLED) {
                ServiceControlResult.UNAVAILABLE
            } else result
        }

        private fun requestStart(context: Context, explicit: Boolean): ServiceControlResult {
            if (Looper.myLooper() != Looper.getMainLooper()) return ServiceControlResult.UNAVAILABLE
            val owner = context.applicationContext as? ControllerApplication ?: return ServiceControlResult.UNAVAILABLE
            if (explicit) {
                val activity = context as? MainActivity ?: return ServiceControlResult.NOT_ALLOWED
                if (!owner.isCurrentForegroundControllerHost(activity)) return ServiceControlResult.NOT_ALLOWED
                val observation = owner.observeControllerService(activity)
                if (observation.bootEnabled == null) return ServiceControlResult.UNAVAILABLE
                if (!observation.canStart) return ServiceControlResult.NOT_ALLOWED
            } else if (!owner.canRequestAutomaticServiceStart()) return ServiceControlResult.NOT_ALLOWED
            val state = componentState(context)
            if (!BootServicePolicy.bootEnabled(state)) return if (state == BootComponentState.DISABLED) ServiceControlResult.DISABLED else ServiceControlResult.UNAVAILABLE
            val generation = owner.controllerServiceStartRequested() ?: return ServiceControlResult.UNAVAILABLE
            return try {
                val intent = Intent(context, ControllerForegroundService::class.java)
                    .setAction(if (explicit) ACTION_EXPLICIT_START else ACTION_START)
                    .putExtra(EXTRA_GENERATION, generation)
                if (context.startForegroundService(intent) == null) throw IllegalStateException()
                ServiceControlResult.REQUESTED
            } catch (_: Exception) {
                // OS denial/force-stop/OEM limits are not bypassed or loop-retried.
                owner.controllerServiceStartRejected(generation)
                ServiceControlResult.UNAVAILABLE
            }
        }

        internal fun stopExplicit(context: Context): ServiceControlResult {
            if (Looper.myLooper() != Looper.getMainLooper()) return ServiceControlResult.UNAVAILABLE
            val activity = context as? MainActivity ?: return ServiceControlResult.NOT_ALLOWED
            val owner = activity.application as? ControllerApplication ?: return ServiceControlResult.UNAVAILABLE
            if (!owner.isCurrentForegroundControllerHost(activity) || !owner.observeControllerService(activity).canStop) {
                return ServiceControlResult.NOT_ALLOWED
            }
            var succeeded = true
            try {
                context.packageManager.setComponentEnabledSetting(ComponentName(context, ControllerBootReceiver::class.java),
                    PackageManager.COMPONENT_ENABLED_STATE_DISABLED, PackageManager.DONT_KILL_APP)
            } catch (_: Exception) { succeeded = false }
            if (componentState(context) != BootComponentState.DISABLED) succeeded = false
            // Cancellation still proceeds if changing the boot setting failed;
            // UNAVAILABLE does not claim the persistent setting was updated.
            owner.shutdownControllerPolicyOwner()
            try {
                val matched = context.stopService(Intent(context, ControllerForegroundService::class.java))
                owner.controllerServiceStopAcknowledged(if (matched) NativeStopObservation.MATCHED_SERVICE else NativeStopObservation.NOT_RUNNING)
            }
            catch (_: Exception) { succeeded = false }
            return if (succeeded) ServiceControlResult.REQUESTED else ServiceControlResult.UNAVAILABLE
        }
    }
}
