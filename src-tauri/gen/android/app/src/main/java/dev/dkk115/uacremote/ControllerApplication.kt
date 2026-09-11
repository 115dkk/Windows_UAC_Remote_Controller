// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote

import android.app.Application
import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import androidx.lifecycle.Lifecycle
import dev.dkk115.uacremote.background.ApplicationPolicyActor
import dev.dkk115.uacremote.background.BootOwnerAction
import dev.dkk115.uacremote.background.BootServicePolicy
import dev.dkk115.uacremote.background.BootDiagnostics
import dev.dkk115.uacremote.background.BootDiagnosticRecord
import dev.dkk115.uacremote.background.BootDiagnosticStage
import dev.dkk115.uacremote.background.BootActivationState
import dev.dkk115.uacremote.background.BootRegistration
import dev.dkk115.uacremote.background.BootRegistrationOperation
import dev.dkk115.uacremote.background.BootStopCompletion
import dev.dkk115.uacremote.background.ServiceControlResult
import dev.dkk115.uacremote.background.ControllerForegroundService
import dev.dkk115.uacremote.background.ControllerServiceState
import dev.dkk115.uacremote.background.ControllerServiceFacts
import dev.dkk115.uacremote.background.ControllerServiceObservation
import dev.dkk115.uacremote.background.PolicyOwnerPhase
import dev.dkk115.uacremote.background.PolicyReply
import dev.dkk115.uacremote.background.PolicyStatus
import dev.dkk115.uacremote.background.UserUnlockObservation
import dev.dkk115.uacremote.background.ResumedHostTrace
import dev.dkk115.uacremote.background.ServiceStartGenerations
import dev.dkk115.uacremote.background.NativeStopObservation
import dev.dkk115.uacremote.background.NativeNotificationRoute
import dev.dkk115.uacremote.background.NativeRequestAction
import dev.dkk115.uacremote.background.NativeRequestActionResult
import dev.dkk115.uacremote.background.NativeRequestPayload
import dev.dkk115.uacremote.background.NativeRequestReadReply
import dev.dkk115.uacremote.background.NativeRequestReview
import dev.dkk115.uacremote.background.NativeRequestRules
import java.lang.ref.WeakReference
import dev.dkk115.uacremote.pairing.PairingScannerDialog
import dev.dkk115.uacremote.pairing.PairingScannerLaunch

/** One Application owner; Direct Boot construction does not touch CE/Rust/keys. */
class ControllerApplication : Application() {
    @Volatile private var policyActor: ApplicationPolicyActor? = null
    private var pairingScanner: PairingScannerDialog? = null // main only, retained through cleanup
    private val main = Handler(Looper.getMainLooper())
    private val readLock = Any()
    private val pendingReads = ArrayList<PendingRead>()
    private var serviceToken: Any? = null
    private var serviceTokenGeneration: Long? = null
    private val serviceGenerations = ServiceStartGenerations()
    private val bootRegistration = BootRegistration(this, ::isCurrentForegroundControllerHost)
    private var serviceListener: ((ControllerServiceState) -> Unit)? = null
    private var serviceWanted = false
    private var serviceStartPending = false
    private var explicitStopRequested = false
    private var shutdownRequestedFor: ApplicationPolicyActor? = null
    private var mayReplaceClosed = false
    private var explicitReplacement = false
    private var ownerFailed = false
    @Volatile private var constructionUncertain = false
    @Volatile private var startRejected = false
    private var state = ControllerServiceState.STOPPED
    private var freshServiceObserver = false
    private val resumedControllerHost = ResumedHostTrace<MainActivity>()
    private var requestWakeOwner: WeakReference<Activity>? = null
    private var requestWake: (() -> Unit)? = null
    private var routeHost: WeakReference<Activity>? = null
    private var pendingRoute: NativeNotificationRoute? = null
    private val controllerHosts = object : Application.ActivityLifecycleCallbacks {
        override fun onActivityPostResumed(activity: Activity) {
            if (activity is MainActivity) {
                resumedControllerHost.resumed(activity)
                pairingScanner?.takeIf { it.activity === activity }?.hostResumed()
                policyActor?.maintainRequests()
                dispatchNotificationRoute(activity)
            }
        }
        override fun onActivityPrePaused(activity: Activity) { clearHost(activity) }
        override fun onActivityDestroyed(activity: Activity) { clearHost(activity) }
        private fun clearHost(activity: Activity) {
            pairingScanner?.takeIf { it.activity === activity }?.hostPaused()
            resumedControllerHost.pausedOrDestroyed(activity)
            bootRegistration.hostRetired(activity)
            if (routeHost?.get() === activity) { routeHost = null; pendingRoute = null }
            if (activity.isDestroyed && requestWakeOwner?.get() === activity) { requestWakeOwner = null; requestWake = null }
        }
        override fun onActivityCreated(activity: Activity, savedInstanceState: Bundle?) = Unit
        override fun onActivityStarted(activity: Activity) = Unit
        override fun onActivityResumed(activity: Activity) = Unit
        override fun onActivityPaused(activity: Activity) = Unit
        override fun onActivityStopped(activity: Activity) = Unit
        override fun onActivitySaveInstanceState(activity: Activity, outState: Bundle) = Unit
    }

    private enum class ReadKind { POLICY, HISTORY }
    private inner class PendingRead(val kind: ReadKind, val callback: (PolicyReply) -> Unit) {
        val started = SystemClock.elapsedRealtime()
        val timeout = Runnable { finishRead(this, PolicyReply.Failed(PolicyStatus.BUSY)) }
    }

    override fun onCreate() {
        super.onCreate()
        registerActivityLifecycleCallbacks(controllerHosts)
        BootDiagnostics.record(BootDiagnosticRecord(BootDiagnosticStage.APPLICATION_CREATE))
        bootRegistration.initialize()
        // Even constructing the actor creates its native-platform/keys wrapper.
        // Only the already-promoted foreground service may request it below.
    }

    /** Passive, fixed metadata for the framework's permission-gated Service.dump.
     * No controller/CE/key lookup, creation, callback or worker wait occurs here.
     * Object identities and request material are deliberately not serialized. */
    internal fun controllerLifecycleDiagnosticLines(): List<String>? {
        if (Looper.myLooper() != Looper.getMainLooper()) return null
        val actor = policyActor
        return listOf(
            "owner_present=${actor != null}",
            "owner_phase=${actor?.lifecyclePhase()?.name ?: "NONE"}",
            "wanted=$serviceWanted",
            "start_pending=$serviceStartPending",
            "application_attached=${serviceToken != null}",
            "construction_uncertain=$constructionUncertain",
            "start_rejected=$startRejected",
            "reported_state=${state.name}",
            "activation_state=${bootRegistration.state.name}",
            "activation_pending=${bootRegistration.pending}",
            "activation_uncertain=${bootRegistration.uncertain}",
        )
    }

    /** Actual framework trace only, never a renderer/authentication boolean. */
    internal fun currentResumedControllerHost(): Activity? {
        if (Looper.myLooper() != Looper.getMainLooper()) return null
        val host = resumedControllerHost.current() ?: return null
        return if (!host.isDestroyed && !host.isFinishing) host else null
    }

    internal fun isCurrentForegroundControllerHost(activity: Activity): Boolean {
        val current = currentResumedControllerHost() as? MainActivity ?: return false
        return current === activity && current.lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED)
    }

    internal fun canOpenPairingScanner(activity: MainActivity): Boolean {
        if (!isCurrentForegroundControllerHost(activity) || pairingScanner != null || activity.pairingPermissionPending() ||
            !serviceWanted || serviceToken == null || explicitStopRequested || !controllerBootActivationEnabled()) return false
        val actor = policyActor ?: return false
        if (actor.lifecyclePhase() != PolicyOwnerPhase.READY || actor.hasPendingPairingScan()) return false
        return try {
            getSystemService(android.app.KeyguardManager::class.java)?.isDeviceSecure == true &&
                ControllerForegroundService.observeUnlock(this) == UserUnlockObservation.UNLOCKED &&
                packageManager.hasSystemFeature(android.content.pm.PackageManager.FEATURE_CAMERA_ANY)
        } catch (_: Exception) { false }
    }

    /** Zero-payload native opening. The original physical binding is retained only as liveness. */
    internal fun openPairingScanner(activity: MainActivity, origin: Any, originCurrent: () -> Boolean,
        callback: (PairingScannerLaunch) -> Unit) {
        check(Looper.myLooper() == Looper.getMainLooper())
        if (!isCurrentForegroundControllerHost(activity) || !originCurrent()) { callback(PairingScannerLaunch.UNAVAILABLE); return }
        if (pairingScanner != null || activity.pairingPermissionPending() || policyActor?.hasPendingPairingScan() == true) {
            callback(PairingScannerLaunch.BUSY); return
        }
        val actor = policyActor
        if (actor == null || !canOpenPairingScanner(activity)) { callback(PairingScannerLaunch.UNAVAILABLE); return }
        val flow = try { PairingScannerDialog(activity, origin, actor,
            { policyActor === actor && actor.lifecyclePhase() == PolicyOwnerPhase.READY &&
                serviceWanted && serviceToken != null && !explicitStopRequested && controllerBootActivationEnabled() &&
                isCurrentForegroundControllerHost(activity) && originCurrent() },
            { finished -> if (pairingScanner === finished) {
                pairingScanner = null
                // One zero-payload snapshot invalidation after ACTUAL release,
                // never to a replacement Activity/WebView or while resources remain.
                if (isCurrentForegroundControllerHost(activity) && originCurrent()) requestSnapshotChanged()
            } }) } catch (_: Exception) { callback(PairingScannerLaunch.UNAVAILABLE); return }
        pairingScanner = flow
        try {
            val opened = flow.show()
            if (!opened || !flow.isShowing() || !isCurrentForegroundControllerHost(activity) || !originCurrent()) {
                flow.close(); callback(PairingScannerLaunch.UNAVAILABLE)
            } else callback(PairingScannerLaunch.OPENED)
        } catch (_: Exception) { flow.close(); callback(PairingScannerLaunch.UNAVAILABLE) }
    }

    internal fun retirePairingScanner(activity: MainActivity, origin: Any) {
        pairingScanner?.takeIf { it.belongsTo(activity, origin) }?.close()
    }
    internal fun pairingScannerHostStopped(activity: MainActivity) { pairingScanner?.takeIf { it.activity === activity }?.close() }
    internal fun pairingScannerRotationChanged(activity: MainActivity) { pairingScanner?.takeIf { it.activity === activity }?.rotationChanged() }

    /** Native listener gets an empty wake only; sticky review is read separately. */
    internal fun observeRequestChanges(activity: Activity, listener: (() -> Unit)?) {
        check(Looper.myLooper() == Looper.getMainLooper())
        if (listener == null) {
            if (requestWakeOwner?.get() === activity) { requestWakeOwner = null; requestWake = null }
        } else if (activity is MainActivity && !activity.isDestroyed) {
            requestWakeOwner = WeakReference(activity); requestWake = listener
        }
    }
    internal fun requestSnapshotChanged() {
        check(Looper.myLooper() == Looper.getMainLooper())
        val host = requestWakeOwner?.get() ?: return
        if (isCurrentForegroundControllerHost(host)) try { requestWake?.invoke() } catch (_: Exception) { }
    }
    internal fun readControllerRequests(activity: Activity, locator: String?, callback: (NativeRequestReadReply) -> Unit) {
        onMain {
            val actor = policyActor
            if (!isCurrentForegroundControllerHost(activity) || actor == null) {
                callback(NativeRequestReadReply.Failed(if (actor == null && preOwnerMutationStatus() == PolicyStatus.BUSY) NativeRequestActionResult.BUSY else NativeRequestActionResult.UNAVAILABLE))
            } else actor.readRequests(locator) { result ->
                val live = policyActor === actor && isCurrentForegroundControllerHost(activity)
                callback(if (live) result else NativeRequestReadReply.Failed(NativeRequestActionResult.UNAVAILABLE))
            }
        }
    }
    internal fun validControllerRequestReply(activity: Activity, value: NativeRequestPayload): Boolean =
        isCurrentForegroundControllerHost(activity) && policyActor?.validRequestReply(value) == true
    internal fun controllerRequestReview(activity: Activity): NativeRequestReview? {
        check(Looper.myLooper() == Looper.getMainLooper())
        if (!isCurrentForegroundControllerHost(activity)) return null
        return try { policyActor?.requestReview() } catch (_: Exception) { null }
    }
    internal fun controllerRequestAction(activity: Activity, locator: String, action: NativeRequestAction, callback: (NativeRequestActionResult) -> Unit) {
        onMain {
            val actor = policyActor
            if (!isCurrentForegroundControllerHost(activity) || actor == null) callback(NativeRequestActionResult.UNAVAILABLE)
            else actor.requestAction(locator, action, activity, null, callback)
        }
    }

    /** Only an existing process-local original handle may consume this selector.
     * Restored Activity state/cold process/unknown locator never starts auth. */
    internal fun receiveRequestIntent(activity: MainActivity, intent: Intent, restored: Boolean) {
        check(Looper.myLooper() == Looper.getMainLooper())
        val route = NativeRequestRules.route(intent) ?: return
        if (!NativeRequestRules.mayRouteActivity(restored, policyActor?.lifecyclePhase() == PolicyOwnerPhase.READY, route.action)) return
        routeHost = WeakReference(activity); pendingRoute = route
        if (isCurrentForegroundControllerHost(activity)) dispatchNotificationRoute(activity)
    }
    private fun dispatchNotificationRoute(activity: Activity) {
        if (routeHost?.get() !== activity || !isCurrentForegroundControllerHost(activity)) return
        val route = pendingRoute ?: return
        routeHost = null; pendingRoute = null // Consume before any asynchronous hop.
        policyActor?.requestAction(route.locator, route.action, activity, route) { requestSnapshotChanged() }
    }
    internal fun denyNotificationRequest(route: NativeNotificationRoute, callback: (NativeRequestActionResult) -> Unit) {
        check(Looper.myLooper() == Looper.getMainLooper())
        val actor = policyActor
        if (route.action != NativeRequestAction.DENY || actor == null) callback(NativeRequestActionResult.UNAVAILABLE)
        else actor.requestAction(route.locator, route.action, null, route, callback)
    }
    internal fun requestTimeChanged() { policyActor?.invalidateRequestTime() }

    /** No actor construction, CE, native key or Rust call occurs while reading. */
    internal fun observeControllerService(activity: Activity): ControllerServiceObservation {
        check(Looper.myLooper() == Looper.getMainLooper())
        return BootServicePolicy.serviceObservation(controllerServiceFacts(), isCurrentForegroundControllerHost(activity))
    }

    private fun controllerServiceFacts() = ControllerServiceFacts(
        ControllerForegroundService.componentState(this), state, serviceWanted, serviceToken != null,
        serviceStartPending, policyActor?.lifecyclePhase(), constructionUncertain, startRejected,
        serviceGenerations.canReserve() || serviceGenerations.current() != null,
        bootRegistration.state, bootRegistration.pending, bootRegistration.uncertain,
    )

    internal fun controllerBootActivationState(): BootActivationState = bootRegistration.state

    internal fun whenControllerBootActivationObserved(callback: (Boolean) -> Unit) = bootRegistration.whenObserved { available ->
        // Always leave the current framework callback before evaluating a
        // visible Activity's STARTED lifecycle or a queued sticky continuation.
        if (!main.post { callback(available) }) callback(false)
    }

    internal fun controllerBootActivationEnabled(): Boolean = BootServicePolicy.effectiveBootEnabled(controllerServiceFacts()) == true

    /** The original real Activity admits a fixed mutation. Persistence is owned
     * by the Application through timeout/rotation; no plugin can replace it. */
    internal fun startControllerServiceExplicit(activity: MainActivity, started: Long, callback: (ServiceControlResult) -> Unit) {
        check(Looper.myLooper() == Looper.getMainLooper())
        if (!isCurrentForegroundControllerHost(activity) || !observeControllerService(activity).canStart) {
            callback(ServiceControlResult.NOT_ALLOWED); return
        }
        bootRegistration.mutate(activity, BootRegistrationOperation.START, started) { result ->
            if (result.failure != null || !isCurrentForegroundControllerHost(activity) ||
                BootServicePolicy.serviceCommandExpired(started, SystemClock.elapsedRealtime()) || !controllerBootActivationEnabled()) {
                controllerServiceStartRejected()
                callback(ServiceControlResult.UNAVAILABLE)
            } else {
                val outcome = ControllerForegroundService.startAfterRegistration(activity, started)
                callback(if (outcome == ServiceControlResult.REQUESTED) outcome else ServiceControlResult.UNAVAILABLE)
            }
        }
    }

    internal fun stopControllerServiceExplicit(activity: MainActivity, started: Long, callback: (ServiceControlResult) -> Unit) {
        check(Looper.myLooper() == Looper.getMainLooper())
        if (!isCurrentForegroundControllerHost(activity) || !observeControllerService(activity).canStop ||
            BootServicePolicy.serviceCommandExpired(started, SystemClock.elapsedRealtime())) {
            callback(ServiceControlResult.NOT_ALLOWED); return
        }
        // Downward actions happen immediately even when the writer is busy or
        // storage is unavailable. A busy STOP is never a claimed durable OFF.
        bootRegistration.cancelStart()
        shutdownControllerPolicyOwner()
        val completion = BootStopCompletion.attempt {
            val matched = stopService(Intent(this, ControllerForegroundService::class.java))
            val observation = if (matched) NativeStopObservation.MATCHED_SERVICE else NativeStopObservation.NOT_RUNNING
            controllerServiceStopAcknowledged(observation)
            observation
        }
        bootRegistration.mutate(activity, BootRegistrationOperation.STOP, started) { result ->
            callback(completion.finish(result, started, SystemClock.elapsedRealtime()))
        }
    }

    /** Automatic starts may not undo an explicit stop, even if persistence failed. */
    internal fun canRequestAutomaticServiceStart(): Boolean {
        check(Looper.myLooper() == Looper.getMainLooper())
        val facts = controllerServiceFacts()
        val allowed = BootServicePolicy.automaticStartAllowed(facts, explicitStopRequested, mayReplaceClosed)
        BootDiagnostics.record(BootDiagnosticRecord(BootDiagnosticStage.AUTOMATIC_ADMISSION,
            component = facts.component, admitted = allowed, activation = facts.activation,
            activationPending = facts.activationPending, activationUncertain = facts.activationUncertain))
        return allowed
    }

    internal fun controllerServiceStartRequested(): Long? {
        check(Looper.myLooper() == Looper.getMainLooper())
        val generation = if (serviceWanted && serviceTokenGeneration != null &&
            serviceGenerations.matches(serviceTokenGeneration)) serviceTokenGeneration
        else serviceGenerations.reserve()
        if (generation == null) { controllerServiceStartRejected(); return null }
        explicitStopRequested = false
        serviceWanted = true
        serviceStartPending = true
        startRejected = false
        if (serviceToken == null || policyActor?.lifecyclePhase() != PolicyOwnerPhase.READY) publish(ControllerServiceState.PREPARING)
        return generation
    }

    internal fun controllerServiceStartRejected(generation: Long? = null, token: Any? = null) = onMain {
        if (generation != null && !serviceGenerations.matches(generation)) return@onMain
        if (token != null && serviceToken !== token) return@onMain
        if (startRejected) return@onMain
        startRejected = true
        BootDiagnostics.record(BootDiagnosticRecord(BootDiagnosticStage.START_REJECTED_LATCHED,
            generationPresent = generation != null, attached = serviceToken != null))
        serviceGenerations.invalidate()
        serviceStartPending = false
        serviceWanted = false
        mayReplaceClosed = false
        explicitReplacement = false
        publish(ControllerServiceState.UNAVAILABLE)
        failReads(PolicyStatus.UNAVAILABLE)
        // A failed foreground promotion/update must not leave an independently
        // running replacement owner. Cleanup retains its existing obligations.
        requestOwnerShutdown(false)
    }

    internal fun attachControllerService(token: Any, listener: (ControllerServiceState) -> Unit): Boolean {
        check(Looper.myLooper() == Looper.getMainLooper())
        if (serviceToken != null && serviceToken !== token) return false
        serviceToken = token
        serviceListener = listener
        freshServiceObserver = true
        return true
    }

    internal fun stickyControllerServiceGeneration(token: Any): Long? {
        check(Looper.myLooper() == Looper.getMainLooper())
        if (serviceToken !== token || !BootServicePolicy.stickyStartAllowed(controllerServiceFacts(), explicitStopRequested, mayReplaceClosed)) return null
        return if (serviceWanted && serviceGenerations.current() != null) serviceGenerations.current()
        else controllerServiceStartRequested()
    }

    internal fun isCurrentControllerServiceGeneration(token: Any, generation: Long?): Boolean {
        check(Looper.myLooper() == Looper.getMainLooper())
        return BootServicePolicy.detachOwnsCurrentGeneration(serviceToken, token,
            serviceGenerations.current(), serviceTokenGeneration, generation)
    }

    internal fun startControllerServiceOwner(token: Any, explicit: Boolean, generation: Long): Boolean {
        check(Looper.myLooper() == Looper.getMainLooper())
        if (serviceToken !== token || explicitStopRequested || !controllerBootActivationEnabled() ||
            !BootServicePolicy.acceptsStartGeneration(serviceGenerations.current(), generation, serviceTokenGeneration)) return false
        serviceTokenGeneration = generation
        serviceWanted = true
        serviceStartPending = false
        startRejected = false
        val phase = policyActor?.lifecyclePhase()
        if (explicit && (phase == PolicyOwnerPhase.FAILED || phase == PolicyOwnerPhase.STOPPING || phase == PolicyOwnerPhase.CLOSED)) {
            mayReplaceClosed = true
            explicitReplacement = true
        }
        reconcileOwner()
        if (explicit && (phase == PolicyOwnerPhase.FAILED || phase == PolicyOwnerPhase.STOPPING)) {
            // Exactly one explicit cleanup request. No polling/retry loop.
            requestOwnerShutdown(true)
        }
        return true
    }

    internal fun detachControllerService(token: Any, generation: Long?) {
        check(Looper.myLooper() == Looper.getMainLooper())
        if (serviceToken !== token) return
        val ownsCurrent = isCurrentControllerServiceGeneration(token, generation)
        serviceToken = null
        serviceTokenGeneration = null
        serviceListener = null
        if (ownsCurrent) {
            serviceGenerations.invalidate()
            serviceStartPending = false
            stopOwner(false)
        } else {
            // An old/unactivated object's destruction cannot stop a newly
            // requested generation or a replacement actor owned by another token.
            publish(if (serviceWanted) ControllerServiceState.PREPARING else stoppedOwnerState())
        }
    }

    /** Only after stopService returned a real OS result (not after an exception).
     * This acknowledges cancellation of pending launch, NOT Service destruction
     * or actor cleanup. Those still require their own token/phase observations. */
    internal fun controllerServiceStopAcknowledged(observation: NativeStopObservation) {
        check(Looper.myLooper() == Looper.getMainLooper())
        if (BootServicePolicy.stopAcknowledgmentClearsPending(serviceGenerations.current(), explicitStopRequested, observation)) {
            serviceStartPending = false
            publish(stoppedOwnerState())
        }
    }

    private fun reconcileOwner() {
        if (!serviceWanted || serviceToken == null || !controllerBootActivationEnabled()) return
        val unlock = ControllerForegroundService.observeUnlock(this)
        val actor = policyActor
        when (BootServicePolicy.ownerAction(unlock, actor?.lifecyclePhase(), mayReplaceClosed, constructionUncertain)) {
            BootOwnerAction.WAIT_FOR_UNLOCK -> { publish(ControllerServiceState.WAITING_FOR_UNLOCK); failReads(PolicyStatus.UNAVAILABLE) }
            BootOwnerAction.UNAVAILABLE -> { publish(ControllerServiceState.UNAVAILABLE); failReads(PolicyStatus.UNAVAILABLE) }
            BootOwnerAction.WAIT_FOR_CLEANUP -> publish(ControllerServiceState.CLEANUP_PENDING)
            BootOwnerAction.KEEP_EXISTING -> {
                publish(if (actor?.lifecyclePhase() == PolicyOwnerPhase.READY) ControllerServiceState.LOCAL_SETTINGS_READY else ControllerServiceState.PREPARING)
                drainReads()
            }
            BootOwnerAction.START_NEW -> createOwner()
        }
    }

    private fun createOwner() {
        // A fresh actual observation at the construction boundary, not a cached
        // broadcast/screen-lock/authentication flag. No DE secret-store fallback.
        if (ControllerForegroundService.observeUnlock(this) != UserUnlockObservation.UNLOCKED) {
            publish(ControllerServiceState.UNAVAILABLE)
            return
        }
        constructionUncertain = true
        try {
            val actor = ApplicationPolicyActor(this)
            policyActor = actor
            shutdownRequestedFor = null
            constructionUncertain = false
            mayReplaceClosed = false
            explicitReplacement = false
            ownerFailed = false
            actor.observeLifecycle { phase -> ownerPhaseChanged(actor, phase) }
            if (!serviceWanted || startRejected) { requestOwnerShutdown(false); return }
            actor.start()
            drainReads()
        } catch (_: Exception) {
            // Never orphan a returned actor or replace an uncertain constructor.
            ownerFailed = true
            mayReplaceClosed = false
            publish(ControllerServiceState.UNAVAILABLE)
            failReads(PolicyStatus.UNAVAILABLE)
            requestOwnerShutdown(false)
        }
    }

    private fun ownerPhaseChanged(actor: ApplicationPolicyActor, phase: PolicyOwnerPhase) {
        if (policyActor !== actor) return
        if (phase != PolicyOwnerPhase.READY) pairingScanner?.close()
        if (phase == PolicyOwnerPhase.FAILED) {
            ownerFailed = true
            if (!explicitReplacement) mayReplaceClosed = false
        }
        if (phase == PolicyOwnerPhase.CLOSED) {
            // CLOSED is published only after actual generated-owner destruction,
            // key-reference cleanup and approval cleanup. No optimistic reset.
            if (serviceWanted && mayReplaceClosed) reconcileOwner()
            else publish(if (serviceWanted) ControllerServiceState.UNAVAILABLE else stoppedOwnerState())
        } else if (serviceWanted) {
            when (actor.lifecyclePhase()) {
                PolicyOwnerPhase.READY -> { publish(ControllerServiceState.LOCAL_SETTINGS_READY); drainReads() }
                PolicyOwnerPhase.NEW, PolicyOwnerPhase.STARTING -> { publish(ControllerServiceState.PREPARING); drainReads() }
                PolicyOwnerPhase.FAILED -> { publish(ControllerServiceState.UNAVAILABLE); failReads(PolicyStatus.UNAVAILABLE) }
                PolicyOwnerPhase.STOPPING -> publish(ControllerServiceState.CLEANUP_PENDING)
                PolicyOwnerPhase.CLOSED -> Unit
            }
        }
    }

    internal fun readControllerPolicy(callback: (PolicyReply) -> Unit) = readWhenStarted(ReadKind.POLICY, callback)
    internal fun readControllerHistory(callback: (PolicyReply) -> Unit) = readWhenStarted(ReadKind.HISTORY, callback)

    internal fun saveControllerPolicy(policyJson: String, callback: (PolicyReply) -> Unit) {
        val actor = policyActor
        if (actor == null) reply(callback, PolicyReply.Failed(preOwnerMutationStatus()))
        else actor.savePolicy(policyJson, callback)
    }

    internal fun clearControllerHistory(callback: (PolicyReply) -> Unit) {
        val actor = policyActor
        if (actor == null) reply(callback, PolicyReply.Failed(preOwnerMutationStatus()))
        else actor.clearHistory(callback)
    }

    private fun readWhenStarted(kind: ReadKind, callback: (PolicyReply) -> Unit) {
        val actor = policyActor
        if (actor != null && actor.lifecyclePhase() in listOf(PolicyOwnerPhase.STARTING, PolicyOwnerPhase.READY)) {
            forwardRead(actor, kind, callback)
            return
        }
        val pending = synchronized(readLock) {
            if (!BootServicePolicy.canQueueRead(pendingReads.size)) null
            else PendingRead(kind, callback).also { pendingReads.add(it) }
        }
        if (pending == null) { reply(callback, PolicyReply.Failed(PolicyStatus.BUSY)); return }
        if (!main.post { prepareRead(pending) }) finishRead(pending, PolicyReply.Failed(PolicyStatus.UNAVAILABLE))
    }

    private fun preOwnerMutationStatus(): PolicyStatus =
        if (!startRejected && !constructionUncertain && ControllerForegroundService.observeUnlock(this) == UserUnlockObservation.UNLOCKED &&
            controllerBootActivationEnabled()) PolicyStatus.BUSY
        else PolicyStatus.UNAVAILABLE

    private fun prepareRead(pending: PendingRead) {
        if (!synchronized(readLock) { pendingReads.contains(pending) }) return
        val now = SystemClock.elapsedRealtime()
        val phase = policyActor?.lifecyclePhase()
        if (startRejected || constructionUncertain || ControllerForegroundService.observeUnlock(this) != UserUnlockObservation.UNLOCKED ||
            !controllerBootActivationEnabled() ||
            (!mayReplaceClosed && (phase == PolicyOwnerPhase.FAILED || phase == PolicyOwnerPhase.CLOSED))) {
            finishRead(pending, PolicyReply.Failed(PolicyStatus.UNAVAILABLE))
        } else if (BootServicePolicy.readExpired(pending.started, now)) {
            finishRead(pending, PolicyReply.Failed(PolicyStatus.BUSY))
        } else {
            val remaining = BootServicePolicy.PRE_OWNER_READ_TIMEOUT_MILLIS - (now - pending.started)
            if (!main.postDelayed(pending.timeout, remaining)) finishRead(pending, PolicyReply.Failed(PolicyStatus.UNAVAILABLE))
            else drainReads()
        }
    }

    private fun drainReads() {
        val actor = policyActor ?: return
        if (actor.lifecyclePhase() !in listOf(PolicyOwnerPhase.STARTING, PolicyOwnerPhase.READY)) return
        val reads = synchronized(readLock) { pendingReads.toList().also { pendingReads.clear() } }
        for (pending in reads) {
            main.removeCallbacks(pending.timeout)
            if (BootServicePolicy.readExpired(pending.started, SystemClock.elapsedRealtime())) reply(pending.callback, PolicyReply.Failed(PolicyStatus.BUSY))
            else forwardRead(actor, pending.kind, pending.callback)
        }
    }

    private fun finishRead(pending: PendingRead, result: PolicyReply) {
        if (!synchronized(readLock) { pendingReads.remove(pending) }) return
        main.removeCallbacks(pending.timeout)
        reply(pending.callback, result)
    }

    private fun failReads(status: PolicyStatus) {
        val reads = synchronized(readLock) { pendingReads.toList().also { pendingReads.clear() } }
        for (pending in reads) { main.removeCallbacks(pending.timeout); reply(pending.callback, PolicyReply.Failed(status)) }
    }

    private fun forwardRead(actor: ApplicationPolicyActor, kind: ReadKind, callback: (PolicyReply) -> Unit) {
        when (kind) {
            ReadKind.POLICY -> actor.readPolicy(callback)
            ReadKind.HISTORY -> actor.readHistory(callback)
        }
    }

    private fun publish(value: ControllerServiceState) {
        if (state == value && !freshServiceObserver) return
        state = value
        freshServiceObserver = false
        try { serviceListener?.invoke(value) } catch (_: Exception) { }
    }

    private fun reply(callback: (PolicyReply) -> Unit, result: PolicyReply) {
        try { callback(result) } catch (_: Exception) { }
    }

    private fun onMain(action: () -> Unit) {
        if (Looper.myLooper() == Looper.getMainLooper()) action()
        else main.post(action)
    }

    private fun stoppedOwnerState(): ControllerServiceState = when {
        constructionUncertain -> ControllerServiceState.UNAVAILABLE
        serviceToken != null || serviceStartPending ||
            (policyActor != null && policyActor?.lifecyclePhase() != PolicyOwnerPhase.CLOSED) -> ControllerServiceState.CLEANUP_PENDING
        else -> ControllerServiceState.STOPPED
    }

    private fun requestOwnerShutdown(explicitRetry: Boolean) {
        val actor = policyActor ?: return
        if (actor.lifecyclePhase() == PolicyOwnerPhase.CLOSED ||
            (shutdownRequestedFor === actor && !explicitRetry)) return
        shutdownRequestedFor = actor
        try { actor.shutdown(explicitRetry) }
        catch (_: Exception) {
            mayReplaceClosed = false
            publish(ControllerServiceState.UNAVAILABLE)
        }
    }

    private fun stopOwner(explicitRetry: Boolean) {
        serviceWanted = false
        explicitReplacement = false
        if (!ownerFailed) mayReplaceClosed = true
        failReads(PolicyStatus.UNAVAILABLE)
        publish(stoppedOwnerState())
        requestOwnerShutdown(explicitRetry)
    }

    /** Only an actual native owner termination may call this; no Activity/exit hook does. */
    internal fun shutdownControllerPolicyOwner() = onMain {
        explicitStopRequested = true
        serviceGenerations.invalidate()
        stopOwner(true)
    }
}
