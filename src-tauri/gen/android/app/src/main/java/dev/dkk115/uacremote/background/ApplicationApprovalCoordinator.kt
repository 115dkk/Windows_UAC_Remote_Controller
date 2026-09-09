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
import dev.dkk115.uacremote.security.NativeApprovalOperation
import dev.dkk115.uacremote.security.DeviceKeyError
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

/** Fixed native result categories. No DER/keys or raw exception reaches a WebView. */
internal sealed class NativeApprovalReply {
    /** A Rust-verified candidate, NOT a sent decision or Windows success. */
    class Prepared(val submission: NativeApprovalSubmission) : NativeApprovalReply()
    object Cancelled : NativeApprovalReply()
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
    private val ownerFailed: () -> Unit,
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
            session.plan = plan
            val deadline = plan.deadlineNanos()
            if (deadline > Long.MAX_VALUE.toULong()) throw IllegalStateException("Native deadline unavailable")
            session.deadlineNanos = deadline.toLong()
            if (session.cancelled.get()) { plan.cancel(); return@work }
            when (val prepared = platform.prepareApproval(plan)) {
                is ApprovalOperationOutcome.Value -> {
                    session.operation = prepared.value
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
                if (session.cleanupFailed.get() || session.cancellationUncertain.get()) return NativeApprovalDrainState.FAILED
                val handlesClosed = synchronized(session.handleLock) { session.handleCleanup.planClosed() }
                return if (DenialDrainCompletion.retired(session.phase() == Phase.TERMINAL, session.jobs.get(),
                    session.operation?.isQuiescent() != false, handlesClosed, current.get() !== session, session.submission.get() == null)) {
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
    fun cleanupOnWorker() { current.get()?.let { cleanup(it) } }
    fun hasPendingCleanup(): Boolean = current.get() != null
    /** Explicit owner shutdown retry or actual owner destruction, not a timer. */
    fun retryCleanup() { current.get()?.let {
        it.cleanupFailed.set(false)
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
            val submission = session.submission.getAndSet(null) ?: return cancel(session, NativeApprovalReply.Unavailable)
            if (submission.isCancelled()) { submission.close(); cancel(session, NativeApprovalReply.Cancelled); return }
            session.prepared.set(true)
            if (session.move(Phase.COMPLETED, Phase.TERMINAL)) deliver(session, NativeApprovalReply.Prepared(submission))
            else submission.close()
            cleanup(session)
            return
        }
        val invalid = synchronized(session.handleLock) {
            if (session.handleCleanup.planClosed()) true else try { session.plan?.isCancelled() != false }
            catch (failure: Throwable) { rethrowFatal(failure); true }
        }
        if (invalid) { cancel(session, NativeApprovalReply.Cancelled); return }
        scheduleExpiry(session)
        if (!session.lease.mayComplete(session.host)) return
        when (session.phase()) {
            Phase.PREPARED -> if (session.move(Phase.PREPARED, Phase.PROMPT)) {
                val operation = session.operation ?: return cancel(session, NativeApprovalReply.Unavailable)
                val shown = operation.present(session.host, { actual, host ->
                    if (actual !== session.operation || !session.lease.isCurrent(host)) {
                        cancel(session, NativeApprovalReply.Cancelled)
                    } else if (session.move(Phase.PROMPT, Phase.AUTHENTICATED)) advance(session)
                }, { actual, _ ->
                    if (actual === session.operation) cancel(session, NativeApprovalReply.Cancelled)
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
                work(session) { finish(session) }
            }
            else -> Unit
        }
    }

    private fun sign(session: Session) {
        if (denialBlocked(session.selection)) { cancel(session, NativeApprovalReply.Cancelled); return }
        if (!session.lease.mayComplete(session.host)) {
            session.move(Phase.SIGNING, if (session.attempt == null) Phase.AUTHENTICATED else Phase.CLAIMED)
            post(session) { advance(session) }; return
        }
        val plan = session.plan ?: throw IllegalStateException("Native plan unavailable")
        val controller = owner() ?: throw IllegalStateException("Native owner unavailable")
        val attempt = session.attempt ?: controller.claimApproval(plan).also { session.attempt = it }
        if (session.cancelled.get()) return
        if (!session.lease.mayComplete(session.host)) {
            session.move(Phase.SIGNING, Phase.CLAIMED); post(session) { advance(session) }; return
        }
        val operation = session.operation ?: throw IllegalStateException("Native operation unavailable")
        when (val signed = operation.complete(attempt)) {
            is ApprovalOperationOutcome.Value -> {
                if (session.cancelled.get()) signed.value.fill(0)
                else {
                    session.der.set(signed.value)
                    if (session.move(Phase.SIGNING, Phase.SIGNED)) post(session) { advance(session) }
                    else session.der.getAndSet(null)?.fill(0)
                }
            }
            is ApprovalOperationOutcome.Failure -> cancel(session, keyFailure(signed.keyError))
        }
    }

    private fun finish(session: Session) {
        if (denialBlocked(session.selection)) { cancel(session, NativeApprovalReply.Cancelled); return }
        if (!session.lease.mayComplete(session.host)) {
            session.move(Phase.FINISHING, Phase.SIGNED); post(session) { advance(session) }; return
        }
        val der = session.der.getAndSet(null) ?: throw IllegalStateException("Native result unavailable")
        try {
            val controller = owner() ?: throw IllegalStateException("Native owner unavailable")
            val attempt = session.attempt ?: throw IllegalStateException("Native claim unavailable")
            val submission = controller.finishApproval(attempt, der)
            if (session.cancelled.get() || !session.lease.isCurrent(session.host) || submission.isCancelled()) {
                submission.close(); cancel(session, NativeApprovalReply.Cancelled); return
            }
            when (session.operation?.releaseAfterFinish()) {
                is ApprovalOperationOutcome.Value -> {
                    session.submission.set(submission)
                    if (session.move(Phase.FINISHING, Phase.COMPLETED)) post(session) { advance(session) }
                    else session.submission.getAndSet(null)?.close()
                }
                else -> { submission.close(); cancel(session, NativeApprovalReply.Unavailable) }
            }
        } finally { der.fill(0) }
    }

    private fun work(session: Session, action: () -> Unit): Boolean {
        session.jobs.incrementAndGet()
        if (!enqueue {
            try { if (!session.cancelled.get()) action() }
            catch (failure: Throwable) {
                rethrowFatal(failure)
                cancel(session, NativeApprovalReply.Unavailable)
                if (fatalOwnerFailure(failure)) ownerFailed()
            }
            finally { session.jobs.decrementAndGet(); cleanup(session) }
        }) {
            session.jobs.decrementAndGet()
            cancel(session, NativeApprovalReply.Unavailable)
            return false
        }
        return true
    }

    private fun cancel(session: Session, reply: NativeApprovalReply, explicitRetry: Boolean = false) {
        val changed = !session.cancelled.getAndSet(true)
        session.lease.invalidate()
        // Both are downward-only. Rust invalidation precedes OS cancellation.
        synchronized(session.handleLock) {
            if (!session.handleCleanup.planClosed() && (!session.cancellationUncertain.get() || explicitRetry)) try { session.plan?.cancel(); session.cancellationUncertain.set(false) }
            catch (failure: Throwable) { rethrowFatal(failure); session.cancellationUncertain.set(true) }
        }
        if (!session.cancellationUncertain.get() || explicitRetry || changed) session.operation?.cancel()
        session.der.getAndSet(null)?.fill(0)
        // A retained prepared wrapper is closed by the worker cursor; a failed
        // close must not disappear because getAndSet(null) ran first.
        session.terminate()
        deliver(session, reply)
        cleanup(session)
        if (changed) nativeProgress()
    }

    private fun cleanup(session: Session) {
        if (session.phase() != Phase.TERMINAL || session.jobs.get() != 0) return
        if (session.operation?.isQuiescent() == false) return
        if (session.cleanupFailed.get()) return
        if (!session.cleanupQueued.compareAndSet(false, true)) return
        if (!enqueue {
            try {
                // Native holder is quiescent; no Signature or live prompt may
                // use these generated handles after terminal cleanup.
                synchronized(session.handleLock) {
                    session.submission.get()?.let { held -> held.close(); session.submission.compareAndSet(held, null) }
                    // At most three exact successful operations. Failed action
                    // remains selected; a retry never repeats a successful close.
                    while (session.handleCleanup.next() != ApprovalHandleCleanupAction.COMPLETE) {
                        val next = session.handleCleanup.next()
                        when (next) {
                            ApprovalHandleCleanupAction.RETIRE -> session.plan?.let { owner()?.retireApproval(it) }
                            ApprovalHandleCleanupAction.CLOSE_ATTEMPT -> session.attempt?.close()
                            ApprovalHandleCleanupAction.CLOSE_PLAN -> session.plan?.close()
                            ApprovalHandleCleanupAction.COMPLETE -> Unit
                        }
                        session.handleCleanup.completed(next)
                    }
                }
                // Publish availability only after every individual close. A
                // failed close leaves its exact retry obligation in this slot.
                current.compareAndSet(session, null)
            } catch (failure: Throwable) {
                rethrowFatal(failure)
                // Latch failure BEFORE finally runs. Ordinary worker traffic
                // must not create an endless immediate retry loop.
                session.cleanupFailed.set(true)
                session.cleanupQueued.set(false)
                if (fatalOwnerFailure(failure)) ownerFailed()
            } finally { nativeProgress() }
        }) session.cleanupQueued.set(false)
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
        val cleanupQueued = AtomicBoolean(false)
        val cleanupFailed = AtomicBoolean(false)
        val cancellationUncertain = AtomicBoolean(false)
        val prepared = AtomicBoolean(false)
        val jobs = AtomicInteger(0)
        val der = AtomicReference<ByteArray?>(null)
        val submission = AtomicReference<NativeApprovalSubmission?>(null)
        val handleLock = Any()
        val handleCleanup = ApprovalHandleCleanup()
        @Volatile var deadlineNanos = 0L
        @Volatile var plan: NativeApprovalPlan? = null
        @Volatile var attempt: NativeApprovalAttempt? = null
        @Volatile var operation: NativeApprovalOperation? = null
        private var phase = Phase.PREPARING
        val expiry = Runnable { if (!prepared.get()) cancel(this, NativeApprovalReply.Cancelled) }
        @Synchronized fun phase(): Phase = phase
        @Synchronized fun move(from: Phase, to: Phase): Boolean {
            if (phase != from || cancelled.get()) return false
            phase = to; return true
        }
        @Synchronized fun terminate() { phase = Phase.TERMINAL }
    }
    private fun rethrowFatal(failure: Throwable) {
        if (failure is VirtualMachineError || failure is ThreadDeath || failure is LinkageError) throw failure
    }
    private fun keyFailure(error: DeviceKeyError?): NativeApprovalReply =
        if (error == DeviceKeyError.LOCK_MISSING) NativeApprovalReply.LockRequired else NativeApprovalReply.Unavailable
    private fun fatalOwnerFailure(failure: Throwable): Boolean = failure is BridgeException &&
        failure !is BridgeException.ApprovalRejected && failure !is BridgeException.Busy &&
        failure !is BridgeException.InvalidPolicy && failure !is BridgeException.HistoryTimeUnavailable
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
