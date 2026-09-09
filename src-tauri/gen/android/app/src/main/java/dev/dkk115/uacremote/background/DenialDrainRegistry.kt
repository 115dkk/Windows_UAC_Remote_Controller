// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.background

import dev.dkk115.uacremote.nativecore.BridgeException
import dev.dkk115.uacremote.nativecore.NativeApprovalDrainState
import dev.dkk115.uacremote.nativecore.NativeDenialAttempt
import dev.dkk115.uacremote.nativecore.NativeDenialOperationState
import dev.dkk115.uacremote.nativecore.NativeDenialScope
import dev.dkk115.uacremote.security.DenialOperationObservation

/** Captures one ACTUAL coordinator session, never a caller's cleanup Boolean. */
internal interface DenialApprovalDrain {
    fun state(): NativeApprovalDrainState
}

/** Synthetic booleans in tests are lifecycle observations, never authentication. */
internal object DenialDrainCompletion {
    fun retired(terminal: Boolean, jobs: Int, operationQuiet: Boolean, handlesClosed: Boolean,
                slotReleased: Boolean, submissionClosed: Boolean): Boolean =
        terminal && jobs == 0 && operationQuiet && handlesClosed && slotReleased && submissionClosed
}

/** Pure exact-close cursor. Failure retains the same object; completed closes never repeat. */
internal class DenialCloseCursor(private val maximum: Int = 128) {
    init { require(maximum in 1..128) }
    private val pending = ArrayList<AutoCloseable>()
    private var uncertain = false
    @Synchronized fun closeOrRetain(value: AutoCloseable) {
        if (pending.any { it === value }) throw IllegalStateException("Native cleanup pending")
        try { value.close() }
        catch (_: Exception) {
            if (pending.size < maximum) pending.add(value) else uncertain = true
            throw IllegalStateException("Native cleanup pending")
        }
    }
    @Synchronized fun retryOnce(): Boolean {
        val iterator = pending.iterator()
        while (iterator.hasNext()) {
            try { iterator.next().close(); iterator.remove() } catch (_: Exception) { }
        }
        return pending.isEmpty() && !uncertain
    }
    @Synchronized fun complete(): Boolean = pending.isEmpty() && !uncertain
    override fun toString(): String = "DenialCloseCursor([redacted])"
}

/** Scope identity joins generated callback wrappers to the retained native job. */
internal class DenialDrainRegistry(
    private val jobs: () -> List<DenialJob>,
    private val capture: (DenialJob) -> DenialApprovalDrain,
    private val releaseOperation: (DenialJob) -> Boolean,
) {
    private val lock = Any()
    private val temporary = DenialCloseCursor()

    fun attachScope(job: DenialJob, value: NativeDenialScope) = synchronized(lock) {
        if (job.scopeClosed || job.nativeReleased) throw BridgeException.NativeUnavailable()
        val held = job.scope
        if (held == null) {
            if (!NativeRequestIdentity.same(job.selection, value.request())) throw BridgeException.NativeUnavailable()
            job.scope = value
        } else {
            if (!held.sameScope(value)) throw BridgeException.NativeUnavailable()
            closeTemporary(value)
        }
    }

    fun attachAttempt(job: DenialJob, value: NativeDenialAttempt): Boolean = synchronized(lock) {
        val scope = job.scope ?: throw BridgeException.NativeUnavailable()
        if (job.scopeClosed || !value.belongsTo(scope)) throw BridgeException.NativeUnavailable()
        if (job.attempt == null) { job.attempt = value; true }
        else { closeTemporary(value); false }
    }

    fun advance(scope: NativeDenialScope): NativeApprovalDrainState = synchronized(lock) {
        try {
            if (!temporary.complete()) throw BridgeException.NativeUnavailable()
            val job = findScope(scope, allowAttach = true)
            val drain = job.drain ?: capture(job).also { job.drain = it }
            drain.state()
        } catch (_: Exception) { throw BridgeException.NativeUnavailable() }
        finally { closeTemporary(scope) }
    }

    fun observe(attempt: NativeDenialAttempt): NativeDenialOperationState = synchronized(lock) {
        try {
            if (!temporary.complete()) throw BridgeException.NativeUnavailable()
            val job = jobs().singleOrNull { candidate ->
                val scope = candidate.scope
                scope != null && !candidate.scopeClosed && attempt.belongsTo(scope)
            } ?: throw BridgeException.NativeUnavailable()
            if (job.registrationUncertain) return@synchronized NativeDenialOperationState.FAILED
            when (job.operation?.observation()) {
                null -> NativeDenialOperationState.NOT_STARTED // Only this job can register/start it.
                DenialOperationObservation.NOT_STARTED -> NativeDenialOperationState.NOT_STARTED
                DenialOperationObservation.RUNNING -> NativeDenialOperationState.RUNNING
                DenialOperationObservation.QUIESCENT -> NativeDenialOperationState.QUIESCENT
                DenialOperationObservation.FAILED -> NativeDenialOperationState.FAILED
            }
        } catch (_: Exception) { throw BridgeException.NativeUnavailable() }
        finally { closeTemporary(attempt) }
    }

    fun release(scope: NativeDenialScope) = synchronized(lock) {
        var argumentHandled = false
        try {
            val job = findScope(scope, allowAttach = false)
            val drain = job.drain?.state() ?: throw BridgeException.NativeUnavailable()
            if (drain != NativeApprovalDrainState.NO_MATCHING_SESSION && drain != NativeApprovalDrainState.RETIRED) {
                throw BridgeException.NativeUnavailable()
            }
            if (!temporary.complete() || !cleanInput(job, false)) throw BridgeException.NativeUnavailable()
            if (!job.operationReleased) {
                if (!releaseOperation(job)) throw BridgeException.NativeUnavailable()
                job.operationReleased = true
            }
            // Release argument first; original scope last. Do not remove the job
            // blocker until Rust returns Released (or confirms full shutdown).
            argumentHandled = true
            closeTemporary(scope)
            synchronized(job.handles) {
                if (!job.scopeClosed) {
                    job.scope?.close() ?: throw BridgeException.NativeUnavailable()
                    job.scopeClosed = true
                }
                job.nativeReleased = true
            }
        } catch (_: Exception) {
            if (!argumentHandled) closeTemporary(scope)
            throw BridgeException.NativeUnavailable()
        }
        // No finally-close: failure must retain an argument whose close failed,
        // and a retained original is only closed by its exact cursor above.
    }

    fun cleanInput(job: DenialJob, explicitRetry: Boolean): Boolean = synchronized(lock) {
        if (job.inputCloseFailed && !explicitRetry) return@synchronized false
        val operation = job.operation
        if (operation != null) {
            if (!operation.discardAndCloseInput(explicitRetry)) return@synchronized false
            job.attemptClosed = operation.inputIsClosed()
            job.der = null
        } else if (job.attempt != null && !job.attemptClosed) {
            try { job.attempt?.close(); job.attemptClosed = true }
            catch (_: Exception) { job.inputCloseFailed = true; return@synchronized false }
        }
        if (explicitRetry) job.inputCloseFailed = false
        !job.inputCloseFailed && !job.registrationUncertain
    }

    /** Call once OUTSIDE Rust admission before the actor's explicit shutdown retry. */
    fun retryNative(job: DenialJob): Boolean = synchronized(lock) {
        // Actor resumes its ONE actual approval session separately, once per
        // explicit stop/retry; do not grant that cursor again for this scope.
        val buffers = cleanInput(job, true)
        temporary.retryOnce() && buffers
    }

    fun closeUnretained(value: AutoCloseable) = synchronized(lock) { closeTemporary(value) }
    fun temporaryCleanupComplete(): Boolean = synchronized(lock) { temporary.complete() }

    private fun findScope(scope: NativeDenialScope, allowAttach: Boolean): DenialJob {
        val all = jobs()
        val existing = all.singleOrNull { it.scope != null && !it.scopeClosed && it.scope!!.sameScope(scope) }
        if (existing != null) return existing
        if (allowAttach) {
            val selection = NativeRequestIdentity.copy(scope.request()) ?: throw BridgeException.NativeUnavailable()
            val pending = all.singleOrNull { it.scope == null && NativeRequestIdentity.same(it.selection, selection) }
            if (pending != null) { pending.scope = scope; return pending }
        }
        throw BridgeException.NativeUnavailable()
    }

    private fun closeTemporary(value: AutoCloseable) {
        if (jobs().any { it.scope === value || it.attempt === value }) return
        try { temporary.closeOrRetain(value) } catch (_: Exception) { throw BridgeException.NativeUnavailable() }
    }
    override fun toString(): String = "DenialDrainRegistry([redacted])"
}
