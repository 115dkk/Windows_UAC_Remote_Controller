// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.background

import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import dev.dkk115.uacremote.nativecore.BridgeException
import dev.dkk115.uacremote.nativecore.MobileController
import dev.dkk115.uacremote.nativecore.NativeDenialAdvance
import dev.dkk115.uacremote.nativecore.NativeDenialAttempt
import dev.dkk115.uacremote.nativecore.NativeDenialScope
import dev.dkk115.uacremote.nativecore.NativeRequestSelection
import dev.dkk115.uacremote.security.DenialSigningException
import dev.dkk115.uacremote.security.NativeDenialOperation
import java.util.concurrent.atomic.AtomicBoolean

internal enum class NativeDenialReply { WAITING, PREPARED, AWAITING_OUTCOME, CANCELLED, RELEASED, UNAVAILABLE, BUSY }
internal enum class DenialStep { RESERVE, ADVANCE, SIGN, FINISH, RETIRE, SETTLE, FAILED }

/** Presentation freshness only; never a signing/authentication permit. */
internal object DenialReplyPolicy {
    fun mayReportPrepared(current: Boolean, stopping: Boolean, cancelled: Boolean, scopeLive: Boolean): Boolean =
        current && !stopping && !cancelled && scopeLive
}

internal object DenialCapacityProgress {
    fun retired(previous: Boolean, current: Boolean): Boolean = !previous && current
    fun <T : Any> others(source: T, all: List<T>): List<T> = all.filter { it !== source }
}

/** Pure bounded blocker ownership; a string key here is NOT request authority. */
internal class DenialFenceBook<T : Any>(private val maximum: Int = 32) {
    init { require(maximum in 1..32) }
    private val values = LinkedHashMap<String, T>()
    @Synchronized fun add(key: String, value: T): Boolean {
        if (values.containsKey(key) || values.size >= maximum) return false
        values[key] = value; return true
    }
    @Synchronized fun get(key: String): T? = values[key]
    @Synchronized fun remove(key: String, value: T): Boolean {
        if (values[key] !== value) return false
        values.remove(key); return true
    }
    @Synchronized fun snapshot(): List<T> = values.values.toList()
}

internal class DenialJob(val key: String, val selection: NativeRequestSelection, val callback: (NativeDenialReply) -> Unit) {
    val handles = Any()
    val cancelled = AtomicBoolean(false)
    @Volatile var scope: NativeDenialScope? = null
    @Volatile var scopeClosed = false
    @Volatile var nativeReleased = false
    @Volatile var attempt: NativeDenialAttempt? = null
    @Volatile var attemptClosed = false
    @Volatile var operation: NativeDenialOperation? = null
    @Volatile var operationReleased = false
    @Volatile var registrationUncertain = false
    @Volatile var inputCloseFailed = false
    @Volatile var der: ByteArray? = null
    @Volatile var drain: DenialApprovalDrain? = null
    @Volatile var step = DenialStep.RESERVE
    @Volatile var cleanupFailed = false
    @Volatile var reservationStarted = false
    @Volatile var nativeRetired = false
    @Volatile var expiry: Runnable? = null
    @Volatile var lastReply: NativeDenialReply? = null
    fun cancel() {
        cancelled.set(true)
        synchronized(handles) {
            if (!scopeClosed) try { scope?.cancel() } catch (_: Exception) { cleanupFailed = true }
        }
        operation?.cancel()
    }
    override fun toString(): String = "DenialJob([redacted])"
}

/** Same Application worker, at most32 blockers and one coalesced queued wake. */
internal class DenialJobs(
    private val platform: AndroidNativePlatform,
    private val owner: () -> MobileController?,
    private val enqueue: (() -> Unit) -> Boolean,
    private val ready: () -> Boolean,
    private val ownerFailed: () -> Unit,
    private val cleanupProgress: () -> Unit,
) {
    private val main = Handler(Looper.getMainLooper())
    private val book = DenialFenceBook<DenialJob>()
    private val queueLock = Any()
    private val pending = LinkedHashSet<DenialJob>()
    private var queued = false
    private val stopping = AtomicBoolean(false)
    private var capture: ((DenialJob) -> DenialApprovalDrain)? = null
    val registry = DenialDrainRegistry(book::snapshot,
        { job -> capture?.invoke(job) ?: throw BridgeException.NativeUnavailable() },
        { job -> job.operation?.let { platform.releaseDenialOperation(it) } ?: !job.registrationUncertain })

    fun bindCapture(value: (DenialJob) -> DenialApprovalDrain) { check(capture == null); capture = value }
    fun blocksApproval(selection: NativeRequestSelection): Boolean = try {
        book.get(NativeRequestIdentity.notificationTag(selection)) != null
    } catch (_: Exception) { true }

    fun request(selection: NativeRequestSelection, callback: (NativeDenialReply) -> Unit) {
        val copied = NativeRequestIdentity.copy(selection)
        if (copied == null || stopping.get() || !ready()) { reply(callback, NativeDenialReply.UNAVAILABLE); return }
        val key = NativeRequestIdentity.notificationTag(copied)
        val existing = book.get(key)
        if (existing != null) {
            reply(callback, if (existing.cleanupFailed) NativeDenialReply.UNAVAILABLE else NativeDenialReply.BUSY)
            wake(existing); return
        }
        val job = DenialJob(key, copied, callback)
        if (!book.add(key, job)) { reply(callback, NativeDenialReply.BUSY); return }
        wake(job) // Blocker is installed BEFORE enqueue/reservation/cancellation.
    }

    fun nativeProgress() {
        for (job in book.snapshot()) if (!job.cleanupFailed && !job.nativeReleased) wake(job)
        if (stopping.get()) cleanupProgress()
    }
    fun externalProgress() { for (job in book.snapshot()) if (!job.cleanupFailed && !job.nativeReleased) wake(job) }
    fun stop() { stopping.set(true); for (job in book.snapshot()) job.cancel() }

    private fun wake(job: DenialJob) {
        if (book.get(job.key) !== job || job.nativeReleased || job.cleanupFailed) return
        synchronized(queueLock) { pending.add(job) }
        schedule()
    }
    private fun schedule() {
        synchronized(queueLock) { if (queued || pending.isEmpty()) return; queued = true }
        if (!enqueue {
            val job = synchronized(queueLock) { pending.firstOrNull()?.also { pending.remove(it) } }
            try { if (job != null) run(job) }
            finally { synchronized(queueLock) { queued = false }; schedule() }
        }) synchronized(queueLock) { queued = false } // Retain pending, never loop on overload.
    }

    private fun run(job: DenialJob) {
        if (book.get(job.key) !== job || job.nativeReleased || job.cleanupFailed) return
        val controller = owner() ?: return
        try {
            if (stopping.get() || job.cancelled.get()) {
                job.cancel()
                registry.cleanInput(job, false)
                if (job.scope != null && !job.scopeClosed) consume(job, controller.settleDenial(job.scope!!))
                return
            }
            if (!ready()) return
            when (job.step) {
                DenialStep.RESERVE -> {
                    job.reservationStarted = true
                    val scope = controller.reserveDenial(job.selection)
                    try { registry.attachScope(job, scope) } catch (failure: Exception) { registry.closeUnretained(scope); throw failure }
                    armExpiry(job)
                    job.step = DenialStep.ADVANCE; wake(job)
                }
                DenialStep.ADVANCE -> consume(job, controller.advanceDenial(requireScope(job)))
                DenialStep.SIGN -> {
                    val attempt = job.attempt ?: throw BridgeException.NativeUnavailable()
                    if (requireScope(job).isCancelled()) { job.cancel(); job.step = DenialStep.SETTLE; wake(job); return }
                    job.der = platform.signDenial(attempt)
                    if (job.cancelled.get() || requireScope(job).isCancelled()) { job.cancel(); registry.cleanInput(job, false); job.step = DenialStep.SETTLE }
                    else job.step = DenialStep.FINISH
                    wake(job) // Separate worker turn before Rust finish.
                }
                DenialStep.FINISH -> {
                    val bytes = job.der ?: throw BridgeException.NativeUnavailable()
                    val result = controller.finishDenial(job.attempt ?: throw BridgeException.NativeUnavailable(), bytes)
                    bytes.fill(0); job.der = null
                    consume(job, result)
                }
                DenialStep.RETIRE -> {
                    if (!registry.cleanInput(job, false)) { failCleanup(job); return }
                    val result = controller.retireDenialNative(requireScope(job))
                    val wasRetired = job.nativeRetired
                    job.nativeRetired = result is NativeDenialAdvance.Prepared || result is NativeDenialAdvance.Released
                    consume(job, result)
                    if (DenialCapacityProgress.retired(wasRetired, job.nativeRetired) && book.get(job.key) === job) wakeOthers(job)
                }
                DenialStep.SETTLE -> consume(job, controller.settleDenial(requireScope(job)))
                DenialStep.FAILED -> Unit
            }
        } catch (_: BridgeException.Busy) {
            notify(job, NativeDenialReply.WAITING) // Same scope/DER/cursor, no immediate retry.
        } catch (_: BridgeException.DenialRejected) {
            job.cancel(); registry.cleanInput(job, false); job.step = DenialStep.SETTLE
            notify(job, NativeDenialReply.CANCELLED)
            // Rust guarantees reserve's DenialRejected is pre-insertion. A
            // post-insertion failure uses a fatal/native/storage category.
            if (job.scope == null) remove(job) else wake(job)
        } catch (_: DenialSigningException) {
            job.cancel(); registry.cleanInput(job, false); job.step = DenialStep.SETTLE
            notify(job, NativeDenialReply.UNAVAILABLE); wake(job)
        } catch (failure: Throwable) {
            rethrowFatal(failure)
            job.cancel(); registry.cleanInput(job, false); failCleanup(job); ownerFailed()
        }
    }

    private fun consume(job: DenialJob, result: NativeDenialAdvance) {
        when (result) {
            is NativeDenialAdvance.Waiting -> { notify(job, NativeDenialReply.WAITING) }
            is NativeDenialAdvance.Ready -> {
                val attempt = result.attempt
                val first = try { registry.attachAttempt(job, attempt) }
                catch (failure: Exception) { registry.closeUnretained(attempt); throw failure }
                if (first) {
                    job.registrationUncertain = true
                    try {
                        job.operation = platform.registerDenialOperation(attempt, ::nativeProgress)
                        job.registrationUncertain = false
                    } catch (failure: DenialSigningException) { job.registrationUncertain = false; throw failure }
                    job.step = DenialStep.SIGN; wake(job)
                }
            }
            is NativeDenialAdvance.Prepared -> {
                job.der?.fill(0); job.der = null
                notify(job, NativeDenialReply.PREPARED)
                if (!job.nativeRetired) { job.step = DenialStep.RETIRE; wake(job) }
                else job.step = DenialStep.ADVANCE // No live transport is fabricated/retried here.
            }
            is NativeDenialAdvance.AwaitingOutcome -> {
                notify(job, NativeDenialReply.AWAITING_OUTCOME)
                if (!job.nativeRetired) { job.step = DenialStep.RETIRE; wake(job) } else job.step = DenialStep.SETTLE
            }
            is NativeDenialAdvance.CleanupPending -> {
                job.cancel(); registry.cleanInput(job, false); job.step = DenialStep.SETTLE
                notify(job, NativeDenialReply.WAITING)
            }
            is NativeDenialAdvance.CleanupFailed -> failCleanup(job)
            is NativeDenialAdvance.Released -> {
                if (!job.nativeReleased) throw BridgeException.NativeUnavailable()
                remove(job); notify(job, NativeDenialReply.RELEASED)
            }
        }
    }

    /** Native cursors only, outside admission. The actor grants ONE Rust owner
     * retry with shutdownNativeOwner after this, never also a per-scope retry. */
    fun prepareShutdownCleanup(explicitRetry: Boolean) {
        for (job in book.snapshot()) {
            job.cancel()
            if (explicitRetry) {
                val resumed = registry.retryNative(job)
                if (resumed) job.cleanupFailed = false
            } else registry.cleanInput(job, false)
        }
    }
    fun ownerShutdownSucceeded(): Boolean {
        for (job in book.snapshot()) {
            if (job.nativeReleased || (job.scope == null && job.attempt == null && job.operation == null)) remove(job)
        }
        return book.snapshot().isEmpty() && registry.temporaryCleanupComplete()
    }
    fun hasPendingCleanup(): Boolean = book.snapshot().isNotEmpty() || !registry.temporaryCleanupComplete()
    fun permitsKeyReferenceCleanup(): Boolean = registry.temporaryCleanupComplete() && book.snapshot().all {
        it.nativeReleased || (it.scope == null && it.attempt == null && it.operation == null && !it.registrationUncertain)
    }

    private fun requireScope(job: DenialJob): NativeDenialScope =
        job.scope?.takeUnless { job.scopeClosed } ?: throw BridgeException.NativeUnavailable()
    private fun failCleanup(job: DenialJob) { job.cleanupFailed = true; job.step = DenialStep.FAILED; notify(job, NativeDenialReply.UNAVAILABLE) }
    private fun remove(job: DenialJob) {
        val removed = book.remove(job.key, job)
        synchronized(queueLock) { pending.remove(job) }
        job.expiry?.let { main.removeCallbacks(it) }; job.expiry = null
        if (removed) wakeOthers(job)
    }
    private fun wakeOthers(source: DenialJob) {
        if (stopping.get()) return
        for (job in DenialCapacityProgress.others(source, book.snapshot())) wake(job)
    }
    private fun armExpiry(job: DenialJob) {
        val deadline = requireScope(job).deadlineNanos()
        val now = SystemClock.elapsedRealtimeNanos()
        if (now < 0 || deadline > Long.MAX_VALUE.toULong()) throw BridgeException.NativeUnavailable()
        val remaining = deadline.toLong() - now
        if (remaining <= 0) { job.cancel(); return }
        val action = Runnable { job.cancel(); wake(job); if (stopping.get()) cleanupProgress() }
        job.expiry = action
        if (!main.postDelayed(action, (remaining / 1_000_000L).coerceAtLeast(1))) throw BridgeException.NativeUnavailable()
    }
    private fun notify(job: DenialJob, value: NativeDenialReply) {
        if (job.lastReply == value) return
        job.lastReply = value
        val action = Runnable {
            val positive = value == NativeDenialReply.PREPARED || value == NativeDenialReply.AWAITING_OUTCOME
            val actual = if (positive) {
                val live = synchronized(job.handles) {
                    if (job.scopeClosed) false
                    else try { job.scope?.isCancelled() == false } catch (_: Exception) { false }
                }
                if (DenialReplyPolicy.mayReportPrepared(book.get(job.key) === job, stopping.get(), job.cancelled.get(), live)) value
                else if (job.cancelled.get() || stopping.get()) NativeDenialReply.CANCELLED else NativeDenialReply.UNAVAILABLE
            } else value
            // No registry/handle/key/provider lock spans the native caller callback.
            try { job.callback(actual) } catch (_: Exception) { }
        }
        if (Looper.myLooper() == Looper.getMainLooper()) action.run() else main.post(action)
    }
    private fun reply(callback: (NativeDenialReply) -> Unit, value: NativeDenialReply) {
        val action = Runnable { try { callback(value) } catch (_: Exception) { } }
        if (Looper.myLooper() == Looper.getMainLooper()) action.run() else main.post(action)
    }
    private fun rethrowFatal(error: Throwable) { if (error is VirtualMachineError || error is ThreadDeath || error is LinkageError) throw error }
    override fun toString(): String = "DenialJobs([redacted], no_live_ingress)"
}
