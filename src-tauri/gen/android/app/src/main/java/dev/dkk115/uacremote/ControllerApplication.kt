// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote

import android.app.Application
import android.app.Activity
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import dev.dkk115.uacremote.background.ApplicationPolicyActor
import dev.dkk115.uacremote.background.BootOwnerAction
import dev.dkk115.uacremote.background.BootServicePolicy
import dev.dkk115.uacremote.background.ControllerForegroundService
import dev.dkk115.uacremote.background.ControllerServiceState
import dev.dkk115.uacremote.background.PolicyOwnerPhase
import dev.dkk115.uacremote.background.PolicyReply
import dev.dkk115.uacremote.background.PolicyStatus
import dev.dkk115.uacremote.background.UserUnlockObservation
import dev.dkk115.uacremote.background.ResumedHostTrace

/** One Application owner; Direct Boot construction does not touch CE/Rust/keys. */
class ControllerApplication : Application() {
    @Volatile private var policyActor: ApplicationPolicyActor? = null
    private val main = Handler(Looper.getMainLooper())
    private val readLock = Any()
    private val pendingReads = ArrayList<PendingRead>()
    private var serviceToken: Any? = null
    private var serviceListener: ((ControllerServiceState) -> Unit)? = null
    private var serviceWanted = false
    private var mayReplaceClosed = false
    private var explicitReplacement = false
    private var ownerFailed = false
    @Volatile private var constructionUncertain = false
    @Volatile private var startRejected = false
    private var state = ControllerServiceState.STOPPED
    private var freshServiceObserver = false
    private val resumedControllerHost = ResumedHostTrace<MainActivity>()
    private val controllerHosts = object : Application.ActivityLifecycleCallbacks {
        override fun onActivityPostResumed(activity: Activity) {
            if (activity is MainActivity) resumedControllerHost.resumed(activity)
        }
        override fun onActivityPrePaused(activity: Activity) { clearHost(activity) }
        override fun onActivityDestroyed(activity: Activity) { clearHost(activity) }
        private fun clearHost(activity: Activity) {
            resumedControllerHost.pausedOrDestroyed(activity)
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
        // Even constructing the actor creates its native-platform/keys wrapper.
        // Only the already-promoted foreground service may request it below.
    }

    /** Actual framework trace only, never a renderer/authentication boolean. */
    internal fun currentResumedControllerHost(): Activity? {
        if (Looper.myLooper() != Looper.getMainLooper()) return null
        val host = resumedControllerHost.current() ?: return null
        return if (!host.isDestroyed && !host.isFinishing) host else null
    }

    internal fun controllerServiceStartRequested() = onMain {
        startRejected = false
        if (policyActor?.lifecyclePhase() != PolicyOwnerPhase.READY) publish(ControllerServiceState.PREPARING)
    }

    internal fun controllerServiceStartRejected() = onMain {
        if (startRejected) return@onMain
        startRejected = true
        serviceWanted = false
        mayReplaceClosed = false
        explicitReplacement = false
        publish(ControllerServiceState.UNAVAILABLE)
        failReads(PolicyStatus.UNAVAILABLE)
        // A failed foreground promotion/update must not leave an independently
        // running replacement owner. Cleanup retains its existing obligations.
        try { policyActor?.shutdown() } catch (_: Exception) { }
    }

    internal fun attachControllerService(token: Any, listener: (ControllerServiceState) -> Unit): Boolean {
        check(Looper.myLooper() == Looper.getMainLooper())
        if (serviceToken != null && serviceToken !== token) return false
        serviceToken = token
        serviceListener = listener
        freshServiceObserver = true
        return true
    }

    internal fun startControllerServiceOwner(token: Any, explicit: Boolean) {
        check(Looper.myLooper() == Looper.getMainLooper())
        if (serviceToken !== token) return
        serviceWanted = true
        startRejected = false
        val phase = policyActor?.lifecyclePhase()
        if (explicit && (phase == PolicyOwnerPhase.FAILED || phase == PolicyOwnerPhase.STOPPING || phase == PolicyOwnerPhase.CLOSED)) {
            mayReplaceClosed = true
            explicitReplacement = true
        }
        reconcileOwner()
        if (explicit && (phase == PolicyOwnerPhase.FAILED || phase == PolicyOwnerPhase.STOPPING)) {
            // Exactly one explicit cleanup request. No polling/retry loop.
            try { policyActor?.shutdown() }
            catch (_: Exception) { publish(ControllerServiceState.UNAVAILABLE) }
        }
    }

    internal fun detachControllerService(token: Any) {
        check(Looper.myLooper() == Looper.getMainLooper())
        if (serviceToken !== token) return
        serviceToken = null
        serviceListener = null
        stopOwner()
    }

    private fun reconcileOwner() {
        if (!serviceWanted || serviceToken == null) return
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
            constructionUncertain = false
            mayReplaceClosed = false
            explicitReplacement = false
            ownerFailed = false
            actor.observeLifecycle { phase -> ownerPhaseChanged(actor, phase) }
            if (!serviceWanted || startRejected) { actor.shutdown(); return }
            actor.start()
            drainReads()
        } catch (_: Exception) {
            // Never orphan a returned actor or replace an uncertain constructor.
            ownerFailed = true
            mayReplaceClosed = false
            publish(ControllerServiceState.UNAVAILABLE)
            failReads(PolicyStatus.UNAVAILABLE)
            try { policyActor?.shutdown() } catch (_: Exception) { }
        }
    }

    private fun ownerPhaseChanged(actor: ApplicationPolicyActor, phase: PolicyOwnerPhase) {
        if (policyActor !== actor) return
        if (phase == PolicyOwnerPhase.FAILED) {
            ownerFailed = true
            if (!explicitReplacement) mayReplaceClosed = false
        }
        if (phase == PolicyOwnerPhase.CLOSED) {
            // CLOSED is published only after actual generated-owner destruction,
            // key-reference cleanup and approval cleanup. No optimistic reset.
            if (serviceWanted && mayReplaceClosed) reconcileOwner()
            else publish(if (serviceWanted) ControllerServiceState.UNAVAILABLE else ControllerServiceState.STOPPED)
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
            BootServicePolicy.bootEnabled(ControllerForegroundService.componentState(this))) PolicyStatus.BUSY
        else PolicyStatus.UNAVAILABLE

    private fun prepareRead(pending: PendingRead) {
        if (!synchronized(readLock) { pendingReads.contains(pending) }) return
        val now = SystemClock.elapsedRealtime()
        val phase = policyActor?.lifecyclePhase()
        if (startRejected || constructionUncertain || ControllerForegroundService.observeUnlock(this) != UserUnlockObservation.UNLOCKED ||
            !BootServicePolicy.bootEnabled(ControllerForegroundService.componentState(this)) ||
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

    private fun stopOwner() {
        serviceWanted = false
        explicitReplacement = false
        if (!ownerFailed) mayReplaceClosed = true
        failReads(PolicyStatus.UNAVAILABLE)
        val actor = policyActor
        publish(if (actor == null || actor.lifecyclePhase() == PolicyOwnerPhase.CLOSED) ControllerServiceState.STOPPED else ControllerServiceState.CLEANUP_PENDING)
        try { actor?.shutdown() }
        catch (_: Exception) {
            mayReplaceClosed = false
            publish(ControllerServiceState.UNAVAILABLE)
        }
    }

    /** Only an actual native owner termination may call this; no Activity/exit hook does. */
    internal fun shutdownControllerPolicyOwner() = onMain { stopOwner() }
}
