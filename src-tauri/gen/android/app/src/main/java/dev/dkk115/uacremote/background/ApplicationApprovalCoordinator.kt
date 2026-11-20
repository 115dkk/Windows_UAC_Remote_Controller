// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.background

import android.app.Activity
import android.app.Application
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import dev.dkk115.uacremote.MainActivity
import dev.dkk115.uacremote.ControllerApplication
import dev.dkk115.uacremote.nativecore.MobileController
import dev.dkk115.uacremote.nativecore.BridgeException
import dev.dkk115.uacremote.nativecore.NativeApprovalAttempt
import dev.dkk115.uacremote.nativecore.NativeApprovalPlan
import dev.dkk115.uacremote.nativecore.NativeApprovalSubmission
import dev.dkk115.uacremote.nativecore.NativeRequestSelection
import dev.dkk115.uacremote.nativecore.NativeApprovalDrainState
import dev.dkk115.uacremote.security.ApprovalOperationOutcome
import dev.dkk115.uacremote.security.ApprovalOperationError
import dev.dkk115.uacremote.security.NativeApprovalOperation
import dev.dkk115.uacremote.security.DeviceKeyError
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

/** Fixed native result categories. No DER/keys or raw exception reaches a WebView. */
internal sealed class NativeApprovalReply {
    /** A Rust-verified candidate, NOT a sent decision or Windows success. */
    class Prepared(val submission: NativeApprovalSubmission, val authenticatedAtNanos: Long? = null,
                   val signedAtNanos: Long? = null) : NativeApprovalReply()
    object Cancelled : NativeApprovalReply()
    object AuthenticationCancelled : NativeApprovalReply()
    object Unavailable : NativeApprovalReply()
    object Busy : NativeApprovalReply()
    object LockRequired : NativeApprovalReply()
    final override fun toString(): String = "NativeApprovalReply([redacted])"
}

/**
 * One auth slot on the existing Application worker/DeviceKeyStore. It does not
 * create another controller/executor/key owner. No background start or public
 * Activity intent alone cannot create a plan: the native request registry and
 * Rust original-request check precede this fixed action.
 */
internal class ApplicationApprovalCoordinator(
    private val application: Application,
    private val platform: AndroidNativePlatform,
    private val owner: () -> MobileController?,
    private val enqueue: (() -> Unit) -> Boolean,
    private val ownerFailed: (Throwable) -> Unit,
    private val denialBlocked: (NativeRequestSelection) -> Boolean,
    private val nativeProgress: () -> Unit,
) : Application.ActivityLifecycleCallbacks {
    private val main = Handler(Looper.getMainLooper())
    private val current = AtomicReference<Session?>(null)
    private val stopped = AtomicBoolean(false)
    // Main-thread only, observed from actual framework callbacks.
    // The foreground service may construct this coordinator after the Activity
    // resumed. Prime only from the Application's actual framework lifecycle
    // trace, on main; no renderer-supplied resumed/authentication boolean.
    private var resumedHost: Activity? = (application as? ControllerApplication)?.currentResumedControllerHost()

    init { application.registerActivityLifecycleCallbacks(this) }

    fun canRequest(selection: NativeRequestSelection): Boolean = !stopped.get() && current.get() == null && !denialBlocked(selection)

    /** Boolean reports bounded job admission only, never authentication. */
    fun request(selection: NativeRequestSelection, host: Activity, callback: (NativeApprovalReply) -> Unit): Boolean {
        if (Looper.myLooper() != Looper.getMainLooper() || stopped.get() || host !is MainActivity ||
            host.application !== application || resumedHost !== host || host.isFinishing || host.isDestroyed) {
            callback(NativeApprovalReply.Unavailable)
            return false
        }
        val copied = NativeRequestIdentity.copy(selection)
        if (copied == null) { callback(NativeApprovalReply.Unavailable); return false }
        if (denialBlocked(copied)) { callback(NativeApprovalReply.Busy); return false }
        val session = Session(copied, host, callback)
        if (!current.compareAndSet(null, session)) { callback(NativeApprovalReply.Busy); return false }
        return work(session) {
            if (denialBlocked(session.selection)) { cancel(session, NativeApprovalReply.Cancelled); return@work }
            val controller = owner() ?: throw IllegalStateException("Native owner unavailable")
            val plan = controller.beginApproval(session.selection)
            session.cleanupOwner.bindPlan(plan)
            val deadline = plan.deadlineNanos()
            if (deadline > Long.MAX_VALUE.toULong()) throw IllegalStateException("Native deadline unavailable")
            session.deadlineNanos = deadline.toLong()
            // Arm the deadline the moment it is known, not when the session
            // reaches COMPLETED. A session waiting on the identity check sits in
            // PRESENTING, and nothing else ever wakes it: if that check does not
            // resolve, the session never becomes terminal, cleanup refuses a
            // session that is not terminal, and the slot it holds is held for
            // the life of the process. Approving then stays grey while denying
            // keeps working, which is exactly what a person reports as the
            // button being dead. The runnable does nothing once the submission
            // has been prepared, so arming it early costs a session nothing.
            scheduleExpiry(session)
            if (session.cancelled.get()) { plan.cancel(); return@work }
            when (val prepared = platform.prepareApproval(plan)) {
                is ApprovalOperationOutcome.Value -> {
                    session.cleanupOwner.bindOperation(prepared.value)
                    if (session.cancelled.get()) prepared.value.cancel()
                    else if (session.move(Phase.PREPARING, Phase.PREPARED)) post(session) { advance(session) }
                }
                is ApprovalOperationOutcome.Failure -> cancel(session, keyFailure(prepared.keyError))
            }
        }
    }

    /** A committed withdrawal invalidates immediately, before a main/UI hop. */
    fun withdraw(selection: NativeRequestSelection) {
        val session = current.get() ?: return
        if (NativeRequestIdentity.same(session.selection, selection)) cancel(session, NativeApprovalReply.Cancelled)
    }
    fun invalidateRequests() { current.get()?.let { cancel(it, NativeApprovalReply.Cancelled) } }

    /** One actual session captured under the native same-request denial blocker. */
    internal fun captureDenialDrain(selection: NativeRequestSelection): DenialApprovalDrain {
        if (!denialBlocked(selection)) throw BridgeException.NativeUnavailable()
        val session = current.get()?.takeIf { NativeRequestIdentity.same(it.selection, selection) }
        if (session == null) return object : DenialApprovalDrain {
            override fun state() = NativeApprovalDrainState.NO_MATCHING_SESSION
        }
        cancel(session, NativeApprovalReply.Cancelled)
        return object : DenialApprovalDrain {
            override fun state(): NativeApprovalDrainState {
                val cleanup = session.cleanupOwner
                if (cleanup.failed() || cleanup.cancellationUncertain()) return NativeApprovalDrainState.FAILED
                return if (DenialDrainCompletion.retired(session.phase() == Phase.TERMINAL, cleanup.jobs(),
                    cleanup.operationQuiescent(), cleanup.handlesClosed(), current.get() !== session, cleanup.submissionReleased())) {
                    NativeApprovalDrainState.RETIRED
                } else NativeApprovalDrainState.PENDING
            }
        }
    }

    /** Explicit request-view departure, not pause/stop/focus loss. */
    fun leaveRequest(host: Activity) {
        val session = current.get() ?: return
        if (session.lease.isCurrent(host)) cancel(session, NativeApprovalReply.Cancelled)
    }

    fun stop() {
        stopped.set(true)
        current.get()?.let { cancel(it, NativeApprovalReply.Cancelled) }
        main.post { application.unregisterActivityLifecycleCallbacks(this); resumedHost = null }
    }

    /** Called by the owning worker's finally paths if ordinary traffic filled it. */
    /**
     * What a failed cleanup costs. It used to cost every later approval: the
     * slot this session holds is exactly what `canRequest` refuses on, so the
     * phone's approve button went grey and stayed grey, with nothing on screen
     * to say why, until the app was force-stopped. Measured on a real device.
     *
     * A close that failed once is not proof it will fail forever, and the
     * handle cursor already guarantees a retry never repeats a close that
     * succeeded, so retrying is safe by construction. The budget is what keeps
     * ordinary worker traffic from turning that into the endless immediate loop
     * the latch was introduced to prevent. Past the budget the slot stays held,
     * exactly as before, because an obligation that cannot be discharged is not
     * something to paper over.
     */
    fun cleanupOnWorker() {
        val session = current.get() ?: return
        // The main-thread deadline above is the first answer; this is the one
        // that does not depend on a looper still being able to run a callback.
        // A session past its own deadline is not going to finish, and only
        // cancelling it makes it terminal enough to be cleaned up.
        //
        // Cancelling is where this pass begins, never where it ends. Returning
        // here skipped the retry below, so an expired session whose cleanup had
        // already failed held the slot for the life of the process: the exact
        // defect the retry exists for, put back one line above it. An expired
        // session is also the most likely one to need that retry.
        //
        // PREPARING comes first for the reason `advance` puts it first: a
        // session in that phase has not read its deadline off the plan yet, and
        // `expired` calls an absent deadline expired. Without this the pass
        // cancels a brand-new approval in the window between the tap that
        // claims the slot and the worker job that begins it, and the person
        // pressing approve sees nothing happen at all.
        // Once handed off, the request/delivery owner enforces the original
        // deadline. Cleanup contention must not cancel that independent result.
        if (!session.prepared.get() && !session.cancelled.get() && session.phase() != Phase.PREPARING && expired(session)) {
            // Which phase it died in is the one thing that says why. The value
            // is a fixed enum position, never a request, a selection or a key.
            if (session.expiryTraced.compareAndSet(false, true)) {
                NativeThrowTrace.measurement("APPROVAL_EXPIRED_ON_WORKER", "phase", session.phase().ordinal.toLong())
            }
            cancel(session, NativeApprovalReply.Cancelled)
        }
        session.cleanupOwner.retryFailed(PolicyOwnerBounds.MAX_CONSECUTIVE_MAINTENANCE_FAILURES)
        cleanup(session)
    }
    fun hasPendingCleanup(): Boolean = current.get() != null
    /** Explicit owner shutdown retry or actual owner destruction, not a timer. */
    fun retryCleanup() { current.get()?.let {
        it.cleanupOwner.retryExplicitly()
        cancel(it, NativeApprovalReply.Cancelled, explicitRetry = true)
        cleanup(it)
    } }

    private fun advance(session: Session) {
        if (session.phase() == Phase.TERMINAL) { cleanup(session); return }
        if (session.phase() == Phase.PREPARING) return
        if (current.get() !== session || session.cancelled.get()) { cleanup(session); return }
        if (denialBlocked(session.selection)) { cancel(session, NativeApprovalReply.Cancelled); return }
        if (session.host.isDestroyed || session.host.isFinishing || !session.lease.isCurrent(session.host)) {
            cancel(session, NativeApprovalReply.Cancelled); return
        }
        if (expired(session)) { cancel(session, NativeApprovalReply.Cancelled); return }
        if (session.phase() == Phase.COMPLETED) {
            scheduleExpiry(session)
            if (!session.lease.mayComplete(session.host)) return
            val submission = session.cleanupOwner.takeSubmission() ?: return cancel(session, NativeApprovalReply.Unavailable)
            if (submission.isCancelled()) { submission.close(); cancel(session, NativeApprovalReply.Cancelled); return }
            session.prepared.set(true)
            val operation = session.cleanupOwner.operation()
            if (session.move(Phase.COMPLETED, Phase.TERMINAL)) deliver(session, NativeApprovalReply.Prepared(submission,
                operation?.authenticationObservationNanos(), operation?.signingObservationNanos()))
            else submission.close()
            cleanup(session)
            return
        }
        val invalid = session.cleanupOwner.planCancelledOrClosed()
        if (invalid) { cancel(session, NativeApprovalReply.Cancelled); return }
        scheduleExpiry(session)
        if (!session.lease.mayComplete(session.host)) return
        when (session.phase()) {
            Phase.PREPARED -> if (session.move(Phase.PREPARED, Phase.PROMPT)) {
                val operation = session.cleanupOwner.operation() ?: return cancel(session, NativeApprovalReply.Unavailable)
                val shown = operation.present(session.host, { actual, host ->
                    if (actual !== session.cleanupOwner.operation() || !session.lease.isCurrent(host)) {
                        cancel(session, NativeApprovalReply.Cancelled)
                    } else if (session.move(Phase.PROMPT, Phase.AUTHENTICATED)) advance(session)
                }, { actual, reason ->
                    if (actual === session.cleanupOwner.operation()) cancel(session,
                        if (reason == ApprovalOperationError.AUTHENTICATION_CANCELLED) NativeApprovalReply.AuthenticationCancelled
                        else NativeApprovalReply.Cancelled)
                })
                if (shown is ApprovalOperationOutcome.Failure) cancel(session, NativeApprovalReply.Unavailable)
            }
            Phase.AUTHENTICATED, Phase.CLAIMED -> {
                val expected = session.phase()
                if (session.move(expected, Phase.SIGNING)) work(session) { sign(session) }
            }
            Phase.SIGNED -> if (session.move(Phase.SIGNED, Phase.FINISHING)) {
                // A separate FIFO worker job: pending PC/domain changes can run
                // after crypto and before finish. Never finish inline in sign.
                if (!session.decision.start()) cancel(session, NativeApprovalReply.Unavailable)
            }
            else -> Unit
        }
    }

    private fun sign(session: Session) {
        if (denialBlocked(session.selection)) { cancel(session, NativeApprovalReply.Cancelled); return }
        if (!session.lease.mayComplete(session.host)) {
            session.move(Phase.SIGNING, if (session.cleanupOwner.attempt() == null) Phase.AUTHENTICATED else Phase.CLAIMED)
            post(session) { advance(session) }; return
        }
        val plan = session.cleanupOwner.plan() ?: throw IllegalStateException("Native plan unavailable")
        val controller = owner() ?: throw IllegalStateException("Native owner unavailable")
        val attempt = session.cleanupOwner.attempt() ?: controller.claimApproval(plan).also {
            session.cleanupOwner.bindAttempt(it)
        }
        if (session.cancelled.get()) return
        if (!session.lease.mayComplete(session.host)) {
            session.move(Phase.SIGNING, Phase.CLAIMED); post(session) { advance(session) }; return
        }
        val operation = session.cleanupOwner.operation() ?: throw IllegalStateException("Native operation unavailable")
        when (val signed = operation.complete(attempt)) {
            is ApprovalOperationOutcome.Value -> {
                if (session.cancelled.get()) signed.value.fill(0)
                else if (session.move(Phase.SIGNING, Phase.SIGNED) && session.decision.accept(signed.value)) {
                    post(session) { advance(session) }
                } else {
                    signed.value.fill(0)
                    cancel(session, NativeApprovalReply.Unavailable)
                }
            }
            is ApprovalOperationOutcome.Failure -> cancel(session, keyFailure(signed.keyError))
        }
    }

    private fun finishPrepared(session: Session, submission: NativeApprovalSubmission): Boolean {
        if (session.cancelled.get() || !session.lease.isCurrent(session.host) || submission.isCancelled()) {
            cancel(session, NativeApprovalReply.Cancelled, decisionWillCleanup = true)
            return false
        }
        return when (session.cleanupOwner.operation()?.releaseAfterFinish()) {
            is ApprovalOperationOutcome.Value -> {
                if (!session.cleanupOwner.holdSubmission(submission)) {
                    cancel(session, NativeApprovalReply.Unavailable, decisionWillCleanup = true)
                    return false
                }
                if (session.move(Phase.FINISHING, Phase.COMPLETED)) {
                    post(session) { advance(session) }
                    true
                } else {
                    session.cleanupOwner.discardSubmission(submission)
                    false
                }
            }
            else -> {
                cancel(session, NativeApprovalReply.Unavailable, decisionWillCleanup = true)
                false
            }
        }
    }

    private fun finishFailed(session: Session, failure: Throwable) {
        rethrowFatal(failure)
        val reply = when {
            failure is BridgeException.Busy -> NativeApprovalReply.Busy
            RequestActionFailurePolicy.requestLocal(failure) -> NativeApprovalReply.Cancelled
            else -> NativeApprovalReply.Unavailable
        }
        cancel(session, reply, decisionWillCleanup = true)
        if (RequestActionFailurePolicy.approvalRetiresOwner(failure)) ownerFailed(failure)
    }

    private fun work(session: Session, action: () -> Unit): Boolean {
        session.cleanupOwner.jobStarted()
        if (!enqueue {
            try { if (!session.cancelled.get()) action() }
            catch (failure: Throwable) {
                rethrowFatal(failure)
                // A busy owner did not start this job's call. Run the job again
                // with what it already holds rather than discard an identity
                // check the person has passed and the signature it produced.
                if (!(failure is BridgeException.Busy && retryAfterBusy(session, action))) {
                    val reply = when {
                        failure is BridgeException.Busy -> NativeApprovalReply.Busy
                        RequestActionFailurePolicy.requestLocal(failure) -> NativeApprovalReply.Cancelled
                        else -> NativeApprovalReply.Unavailable
                    }
                    // Reject this attempt without retrying authentication/signing.
                    // Its exact session/handles still own all cancellation cleanup.
                    cancel(session, reply)
                    if (RequestActionFailurePolicy.approvalRetiresOwner(failure)) ownerFailed(failure)
                }
            }
            finally { session.cleanupOwner.jobFinished(); cleanup(session) }
        }) {
            session.cleanupOwner.jobFinished()
            cancel(session, NativeApprovalReply.Unavailable)
            return false
        }
        return true
    }

    /** True when the same job was scheduled to run again. The prompt is never
     * shown again and nothing is signed again: the job repeats one owner call
     * that was not admitted, inside this session's deadline and budget. */
    private fun retryAfterBusy(session: Session, action: () -> Unit): Boolean {
        if (stopped.get() || session.cancelled.get() || current.get() !== session) return false
        val delay = session.busyRetry.next() ?: return false
        if (session.busyRetry.waits() == 1) NativeThrowTrace.measurement("APPROVAL_WORK_BUSY", "waits", 1)
        return main.postDelayed({ if (!session.cancelled.get() && current.get() === session) work(session, action) }, delay)
    }

    private fun cancel(
        session: Session,
        reply: NativeApprovalReply,
        explicitRetry: Boolean = false,
        decisionWillCleanup: Boolean = false,
    ) {
        val changed = !session.cancelled.getAndSet(true)
        session.lease.invalidate()
        // Both are downward-only. Rust invalidation precedes OS cancellation.
        session.cleanupOwner.cancelPlan(explicitRetry)?.let(::rethrowFatal)
        if (!session.cleanupOwner.cancellationUncertain() || explicitRetry || changed) {
            session.cleanupOwner.operation()?.cancel()
        }
        // A retained prepared wrapper is closed by the worker cursor; a failed
        // close must not disappear because getAndSet(null) ran first.
        session.terminate()
        deliver(session, reply)
        if (!decisionWillCleanup && !session.decision.cancel()) cleanup(session)
        if (changed) nativeProgress()
    }

    private fun cleanup(session: Session) = session.cleanupOwner.requestCleanup()

    private fun cleanupFailure(action: ApprovalCleanupAction, failure: Throwable, first: Boolean) {
        rethrowFatal(failure)
        if (first) NativeThrowTrace.note(cleanupSite(action), failure)
        if (RequestActionFailurePolicy.approvalCleanupRetiresOwner(failure)) ownerFailed(failure)
    }

    private fun cleanupSite(action: ApprovalCleanupAction): String = when (action) {
        ApprovalCleanupAction.CLOSE_SUBMISSION -> "APPROVAL_CLOSE_SUBMISSION"
        ApprovalCleanupAction.RETIRE -> "APPROVAL_RETIRE"
        ApprovalCleanupAction.CLOSE_ATTEMPT -> "APPROVAL_CLOSE_ATTEMPT"
        ApprovalCleanupAction.CLOSE_PLAN -> "APPROVAL_CLOSE_PLAN"
        ApprovalCleanupAction.COMPLETE -> "APPROVAL_CLEANUP_COMPLETE"
    }

    private fun post(session: Session, action: () -> Unit) {
        if (!main.post(action)) cancel(session, NativeApprovalReply.Unavailable)
    }
    private fun deliver(session: Session, reply: NativeApprovalReply) {
        if (!session.delivered.compareAndSet(false, true)) {
            if (reply is NativeApprovalReply.Prepared) reply.submission.close()
            return
        }
        val deliver = Runnable {
            main.removeCallbacks(session.expiry)
            val actual = if (reply is NativeApprovalReply.Prepared &&
                (session.cancelled.get() || !session.lease.mayComplete(session.host) || reply.submission.isCancelled())) {
                reply.submission.close(); NativeApprovalReply.Cancelled
            } else reply
            try { session.callback(actual) } catch (failure: Throwable) { rethrowFatal(failure) }
        }
        if (Looper.myLooper() == Looper.getMainLooper()) deliver.run()
        else if (!main.post(deliver) && reply is NativeApprovalReply.Prepared) reply.submission.close()
    }
    private fun scheduleExpiry(session: Session) {
        main.removeCallbacks(session.expiry)
        val remaining = session.deadlineNanos - SystemClock.elapsedRealtimeNanos()
        if (remaining <= 0 || !main.postDelayed(session.expiry, (remaining / 1_000_000L).coerceAtLeast(1))) {
            cancel(session, NativeApprovalReply.Cancelled)
        }
    }
    private fun expired(session: Session): Boolean {
        val now = SystemClock.elapsedRealtimeNanos()
        return now < 0 || session.deadlineNanos <= 0 || now >= session.deadlineNanos
    }

    override fun onActivityPostResumed(activity: Activity) {
        if (activity !is MainActivity || stopped.get()) return
        resumedHost = activity
        current.get()?.let { if (it.lease.resumed(activity)) advance(it) }
    }
    override fun onActivityPrePaused(activity: Activity) {
        if (resumedHost === activity) resumedHost = null
        current.get()?.lease?.paused(activity)
    }
    override fun onActivityDestroyed(activity: Activity) {
        if (resumedHost === activity) resumedHost = null
        current.get()?.let { if (it.lease.isCurrent(activity)) cancel(it, NativeApprovalReply.Cancelled) }
    }
    override fun onActivityCreated(activity: Activity, state: Bundle?) = Unit
    override fun onActivityStarted(activity: Activity) = Unit
    override fun onActivityResumed(activity: Activity) = Unit
    override fun onActivityPaused(activity: Activity) = Unit
    override fun onActivityStopped(activity: Activity) = Unit
    override fun onActivitySaveInstanceState(activity: Activity, state: Bundle) = Unit

    private enum class Phase { PREPARING, PREPARED, PROMPT, AUTHENTICATED, CLAIMED, SIGNING, SIGNED, FINISHING, COMPLETED, TERMINAL }
    private inner class Session(val selection: NativeRequestSelection, val host: Activity, val callback: (NativeApprovalReply) -> Unit) {
        val lease = ApprovalHostLease(host)
        val cancelled = AtomicBoolean(false)
        val delivered = AtomicBoolean(false)
        val busyRetry = ApprovalBusyRetry()
        val expiryTraced = AtomicBoolean(false)
        val prepared = AtomicBoolean(false)
        val cleanupOwner = ApprovalCleanupOwner(
            platform = object : ApprovalCleanupPlatform<NativeApprovalPlan, NativeApprovalAttempt,
                NativeApprovalSubmission, NativeApprovalOperation> {
                override fun closeSubmission(submission: NativeApprovalSubmission) = submission.close()
                override fun retire(plan: NativeApprovalPlan) {
                    val controller = owner() ?: throw BridgeException.Closed()
                    controller.retireApproval(plan)
                }
                override fun closeAttempt(attempt: NativeApprovalAttempt) = attempt.close()
                override fun closePlan(plan: NativeApprovalPlan) = plan.close()
                override fun operationQuiescent(operation: NativeApprovalOperation): Boolean = operation.isQuiescent()
                override fun cancelPlan(plan: NativeApprovalPlan) = plan.cancel()
                override fun planCancelled(plan: NativeApprovalPlan): Boolean = plan.isCancelled()
                override fun retirementBusy(failure: Throwable): Boolean = failure is BridgeException.Busy
            },
            enqueue = enqueue,
            defer = { delay, action -> main.postDelayed(action, delay) },
            onComplete = { waits ->
                if (current.compareAndSet(this, null)) {
                    NativeThrowTrace.measurement("APPROVAL_CLEANUP_COMPLETE", "admission_waits", waits.toLong())
                }
            },
            onRefused = { reason ->
                NativeThrowTrace.measurement("APPROVAL_CLEANUP_REFUSED", "reason", reason.ordinal.toLong())
            },
            onFailure = { action, failure, first -> cleanupFailure(action, failure, first) },
            onRetireBusy = { NativeThrowTrace.measurement("APPROVAL_RETIRE_BUSY", "waits", 1) },
            onWakeRejected = { NativeThrowTrace.measurement("APPROVAL_CLEANUP_WAKE", "posted", 0) },
            onProgress = nativeProgress,
        )
        val decision = ApprovalDecisionCoordinator(
            platform = object : ApprovalDecisionPlatform<NativeApprovalSubmission> {
                override fun finish(signedDecision: ByteArray): NativeApprovalSubmission {
                    if (denialBlocked(selection)) throw BridgeException.RequestUnavailable()
                    val controller = owner() ?: throw IllegalStateException("Native owner unavailable")
                    val claimed = cleanupOwner.attempt() ?: throw IllegalStateException("Native claim unavailable")
                    return controller.finishApproval(claimed, signedDecision)
                }
                override fun close(submission: NativeApprovalSubmission) = submission.close()
                override fun busy(failure: Throwable): Boolean = failure is BridgeException.Busy
            },
            enqueue = enqueue,
            defer = { delay, action -> main.postDelayed(action, delay) },
            onPrepared = { finishPrepared(this, it) },
            onFailure = { finishFailed(this, it) },
            cleanup = { cleanup(this) },
            ready = { lease.mayComplete(host) },
            onDeferred = {
                if (move(Phase.FINISHING, Phase.SIGNED)) post(this) { advance(this) }
            },
            onJobStarted = cleanupOwner::jobStarted,
            onJobFinished = { cleanupOwner.jobFinished() },
        )
        @Volatile var deadlineNanos = 0L
        private var phase = Phase.PREPARING
        val expiry = Runnable { if (!prepared.get()) cancel(this, NativeApprovalReply.Cancelled) }
        @Synchronized fun phase(): Phase = phase
        @Synchronized fun move(from: Phase, to: Phase): Boolean {
            if (phase != from || cancelled.get()) return false
            phase = to
            if (to == Phase.TERMINAL) cleanupOwner.terminal()
            return true
        }
        @Synchronized fun terminate() {
            phase = Phase.TERMINAL
            cleanupOwner.terminal()
        }
    }
    private fun rethrowFatal(failure: Throwable) {
        if (failure is VirtualMachineError || failure is ThreadDeath || failure is LinkageError) throw failure
    }
    private fun keyFailure(error: DeviceKeyError?): NativeApprovalReply =
        if (error == DeviceKeyError.LOCK_MISSING) NativeApprovalReply.LockRequired else NativeApprovalReply.Unavailable
}

internal object NativeRequestIdentity {
    fun copy(value: NativeRequestSelection): NativeRequestSelection? {
        val parts = listOf(value.pc, value.epoch, value.request)
        if (parts.any { it.size != 32 }) return null
        val copied = parts.map { it.copyOf() }
        if (copied.any { it.all { byte -> byte == 0.toByte() } }) return null
        return NativeRequestSelection(copied[0], copied[1], copied[2])
    }
    fun same(left: NativeRequestSelection, right: NativeRequestSelection): Boolean =
        left.pc.contentEquals(right.pc) && left.epoch.contentEquals(right.epoch) && left.request.contentEquals(right.request)
    fun notificationTag(value: NativeRequestSelection): String {
        val copied = copy(value) ?: throw IllegalArgumentException("Invalid native request identity")
        val alphabet = "0123456789abcdef"
        fun hex(bytes: ByteArray): String = buildString(64) {
            for (byte in bytes) { val value = byte.toInt() and 255; append(alphabet[value ushr 4]); append(alphabet[value and 15]) }
        }
        return "request:${hex(copied.pc)}:${hex(copied.epoch)}:${hex(copied.request)}"
    }
}
