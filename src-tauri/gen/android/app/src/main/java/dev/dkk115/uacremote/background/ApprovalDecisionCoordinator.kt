// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.background

/**
 * Owns one accepted signed decision from its first worker handoff through either
 * native submission or terminal cleanup. Android lifecycle and authentication
 * stay in [ApplicationApprovalCoordinator]; this owner is the pure-JVM seam for
 * the retry promised by ADR 0048.
 */
internal interface ApprovalDecisionPlatform<Submission> {
    fun finish(signedDecision: ByteArray): Submission
    fun close(submission: Submission)
    fun busy(failure: Throwable): Boolean
}

internal class ApprovalDecisionCoordinator<Submission>(
    private val platform: ApprovalDecisionPlatform<Submission>,
    private val enqueue: (() -> Unit) -> Boolean,
    private val defer: (Long, () -> Unit) -> Boolean,
    private val onPrepared: (Submission) -> Boolean,
    private val onFailure: (Throwable) -> Unit,
    private val cleanup: () -> Unit,
    private val ready: () -> Boolean = { true },
    private val onDeferred: () -> Unit = {},
    private val onJobStarted: () -> Unit = {},
    private val onJobFinished: () -> Unit = {},
) {
    private val lock = Any()
    private val retry = ApprovalBusyRetry()
    private var decision: ByteArray? = null
    private var inFlightDecision: ByteArray? = null
    private var accepted = false
    private var started = false
    private var terminal = false
    private var transferred = false
    private var jobs = 0
    private var cleanupRunning = false
    private var cleanupComplete = false

    /** Takes ownership of [signedDecision] exactly once. */
    fun accept(signedDecision: ByteArray): Boolean = synchronized(lock) {
        if (accepted || terminal || transferred || cleanupComplete) return@synchronized false
        decision = signedDecision
        accepted = true
        true
    }

    /** Starts a separate worker job after signing; an enqueue refusal is terminal. */
    fun start(): Boolean {
        synchronized(lock) {
            if (!accepted || started || terminal || transferred) return false
            started = true
        }
        queueFinish()
        return true
    }

    /**
     * Cancels accepted work without clearing bytes currently borrowed by the
     * synchronous native call. That call clears them before cleanup may run.
     */
    fun cancel(): Boolean {
        val pending = synchronized(lock) {
            if (!accepted || terminal || transferred || cleanupComplete) return false
            terminal = true
            decision.also { decision = null }
        }
        pending?.fill(0)
        tryCleanup()
        return true
    }

    fun hasPendingDecision(): Boolean = synchronized(lock) { accepted && !transferred && !cleanupComplete }

    private fun queueFinish() {
        synchronized(lock) {
            if (terminal || transferred || cleanupComplete) return
            jobs++
        }
        onJobStarted()
        if (!enqueue {
                try {
                    finishOnWorker()
                } finally {
                    synchronized(lock) { jobs-- }
                    onJobFinished()
                    tryCleanup()
                }
            }) {
            synchronized(lock) { jobs-- }
            onJobFinished()
            fail(IllegalStateException("Approval decision worker rejected"))
        }
    }

    private fun finishOnWorker() {
        if (!ready()) {
            val deferred = synchronized(lock) {
                if (terminal || transferred || cleanupComplete) false
                else {
                    started = false
                    true
                }
            }
            if (deferred) onDeferred()
            return
        }
        val bytes = synchronized(lock) {
            if (terminal || transferred || cleanupComplete || inFlightDecision != null) return
            val owned = decision ?: return
            decision = null
            inFlightDecision = owned
            owned
        }
        val submission = try {
            platform.finish(bytes)
        } catch (failure: Throwable) {
            if (busy(failure) && retainForRetry(bytes) && scheduleRetry()) return
            clearInFlight(bytes)
            bytes.fill(0)
            fail(failure)
            return
        }

        clearInFlight(bytes)
        bytes.fill(0)
        if (synchronized(lock) { terminal || cleanupComplete }) {
            closeRejected(submission)
            return
        }

        val retained = try {
            onPrepared(submission)
        } catch (failure: Throwable) {
            closeRejected(submission, failure)
            return
        }
        if (!retained) {
            closeRejected(submission)
            return
        }
        synchronized(lock) {
            transferred = true
            decision = null
        }
    }

    private fun closeRejected(submission: Submission, cause: Throwable? = null) {
        try {
            platform.close(submission)
        } catch (failure: Throwable) {
            fail(failure)
            return
        }
        if (cause == null) terminate() else fail(cause)
    }

    private fun busy(failure: Throwable): Boolean = try {
        platform.busy(failure)
    } catch (_: Exception) {
        false
    }

    private fun retainForRetry(bytes: ByteArray): Boolean = synchronized(lock) {
        if (inFlightDecision !== bytes) return@synchronized false
        inFlightDecision = null
        if (terminal || cleanupComplete) false else {
            decision = bytes
            true
        }
    }.also { retained -> if (!retained) bytes.fill(0) }

    private fun scheduleRetry(): Boolean {
        val delay = retry.next() ?: return false
        return try {
            defer(delay) { queueFinish() }
        } catch (_: Exception) {
            false
        }
    }

    private fun clearInFlight(bytes: ByteArray) {
        synchronized(lock) {
            if (inFlightDecision === bytes) inFlightDecision = null
        }
    }

    private fun fail(failure: Throwable) {
        var pending: ByteArray? = null
        val newlyTerminal = synchronized(lock) {
            if (terminal || transferred || cleanupComplete) false
            else {
                terminal = true
                pending = decision
                decision = null
                true
            }
        }
        pending?.fill(0)
        if (newlyTerminal) onFailure(failure)
        tryCleanup()
    }

    private fun terminate() {
        synchronized(lock) { terminal = true }
        tryCleanup()
    }

    private fun tryCleanup() {
        val run = synchronized(lock) {
            if (!terminal || jobs != 0 || inFlightDecision != null || cleanupRunning || cleanupComplete) false
            else {
                cleanupRunning = true
                true
            }
        }
        if (!run) return
        var complete = false
        try {
            cleanup()
            complete = true
        } finally {
            synchronized(lock) {
                cleanupRunning = false
                if (complete) {
                    cleanupComplete = true
                    decision = null
                }
            }
        }
    }
}
