// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.security

import android.os.Looper
import dev.dkk115.uacremote.nativecore.NativeDenialAttempt

/** Exact registered one-shot input. No authentication UI, key or Signature getter. */
internal class NativeDenialOperation internal constructor(
    private val original: NativeDenialAttempt,
    perform: (NativeDenialAttempt) -> ByteArray,
    private val progress: () -> Unit,
) {
    private val lock = Any()
    private val policy = DenialOperationPolicy()
    private var perform: ((NativeDenialAttempt) -> ByteArray)? = perform
    private var der: ByteArray? = null
    private var inputClosed = false
    private var cancelFailed = false
    private var closeFailed = false

    internal fun owns(input: NativeDenialAttempt): Boolean = original === input
    fun sign(): ByteArray {
        if (Looper.myLooper() == Looper.getMainLooper()) throw DenialSigningException(DenialSigningError.WRONG_THREAD)
        if (!policy.begin()) throw DenialSigningException(DenialSigningError.ALREADY_USED)
        var result: ByteArray? = null
        try {
            if (original.isCancelled()) throw DenialSigningException(DenialSigningError.CANCELLED)
            val signer = synchronized(lock) { perform } ?: throw DenialSigningException(DenialSigningError.ALREADY_USED)
            val value = signer(original)
            result = value
            synchronized(lock) {
                if (!DenialSigningPolicy.validDerLength(value.size) || original.isCancelled() || !policy.mayReturn()) {
                    throw DenialSigningException(DenialSigningError.CANCELLED)
                }
                der = value
            }
            result = null
            return value // SAME bounded array; held here until finish/discard.
        } finally {
            result?.fill(0)
            policy.returned()
            try { progress() } catch (_: Exception) { /* Wake failure cannot replace the native result. */ }
        }
    }

    /** Downward only; cleanup never closes a wrapper while provider work runs. */
    fun cancel() {
        policy.cancel()
        synchronized(lock) {
            if (!inputClosed && !cancelFailed && !closeFailed) try { original.cancel() }
            catch (_: Exception) { cancelFailed = true; policy.cleanupFailed() }
        }
    }

    fun discardAndCloseInput(explicitRetry: Boolean = false): Boolean = synchronized(lock) {
        if (!policy.mayClean()) return false
        if (explicitRetry) {
            if (cancelFailed && !inputClosed) {
                try { original.cancel(); cancelFailed = false }
                catch (_: Exception) { return false }
            }
            policy.retryCleanup()
        }
        if (policy.observation() == DenialOperationObservation.FAILED) return false
        der?.fill(0); der = null
        perform = null // No later provider start, including failed-before-sign.
        if (!inputClosed) {
            try { original.close(); inputClosed = true; closeFailed = false }
            catch (_: Exception) { closeFailed = true; policy.cleanupFailed(); return false }
        }
        policy.cleaned()
        true
    }

    fun observation(): DenialOperationObservation = policy.observation()
    fun inputIsClosed(): Boolean = synchronized(lock) { inputClosed }
    override fun toString(): String = "NativeDenialOperation([redacted])"
}
