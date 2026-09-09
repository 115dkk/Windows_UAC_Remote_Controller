// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.security

import android.os.Looper
import dev.dkk115.uacremote.nativecore.NativeCertificateVerify
import dev.dkk115.uacremote.nativecore.NativeTransportBinding

/**
 * Transient, fixed TRANSPORT-role signer on the existing DeviceKeyStore. This
 * object exposes neither a key/Signature nor a sign(bytes) method. Its private
 * callback captures the original canonical registration/reference exactly once.
 * Rust alone constructs the binding and actual one-shot TLS input objects.
 *
 * Native callbacks run directly off main. Never synchronously dispatch them to
 * the Application worker: Rust may be waiting on this very callback there.
 * close invalidates only this TLS binding, never canonical persistent key refs.
 * Generated argument-wrapper close belongs to AndroidNativePlatform after the
 * actual callback returns; this holder never destroys an in-flight wrapper.
 */
internal class NativeTransportSigner internal constructor(
    private val binding: NativeTransportBinding,
    private val bindingId: ULong,
    private val signFrame: (NativeCertificateVerify) -> TransportSignerOutcome<ByteArray>,
    private val released: (NativeTransportSigner) -> Unit,
) {
    private val policy = TransportSignerPolicy()
    private val cleanupLock = Any()
    private var nativeClosed = false
    private var releaseReported = false

    fun sign(input: NativeCertificateVerify): TransportSignerOutcome<ByteArray> {
        if (Looper.myLooper() == Looper.getMainLooper()) return TransportSignerOutcome.Failure(TransportSignerError.WRONG_THREAD)
        policy.begin()?.let { return TransportSignerOutcome.Failure(it) }
        var ownedDer: ByteArray? = null
        try {
            if (input.bindingId() != bindingId || !input.belongsTo(binding)) return reject(TransportSignerError.IDENTITY_MISMATCH)
            if (binding.isClosed() || input.isCancelled()) return reject(TransportSignerError.CLOSED)
            val der = when (val result = signFrame(input)) {
                is TransportSignerOutcome.Failure -> { close(); return result }
                is TransportSignerOutcome.Value -> result.value
            }
            ownedDer = der
            if (!ClientCertificateVerifyPolicy.validDerLength(der.size)) return reject(TransportSignerError.SIGNING_FAILED)
            if (binding.isClosed() || input.isCancelled() || !policy.completionAllowed()) return reject(TransportSignerError.CLOSED)
            // A later native close can still invalidate this returned DER; Rust
            // must recheck its binding and the channel verifies the actual key.
            val result = TransportSignerOutcome.Value(der)
            ownedDer = null
            return result
        } catch (_: Exception) {
            return reject(TransportSignerError.NATIVE_UNAVAILABLE)
        } finally {
            ownedDer?.fill(0)
            policy.returned()
            reportQuiescence()
        }
    }

    fun close(): TransportSignerOutcome<Unit> {
        policy.close()
        if (!synchronized(cleanupLock) { nativeClosed }) {
            try {
                binding.closeBinding()
                synchronized(cleanupLock) { nativeClosed = true }
            } catch (_: Exception) {
                return TransportSignerOutcome.Failure(TransportSignerError.CLEANUP_PENDING)
            }
        }
        reportQuiescence()
        return if (isQuiescent()) TransportSignerOutcome.Value(Unit)
            else TransportSignerOutcome.Failure(TransportSignerError.BUSY)
    }

    fun isQuiescent(): Boolean = policy.isQuiescent() && synchronized(cleanupLock) { nativeClosed }

    private fun reject(error: TransportSignerError): TransportSignerOutcome.Failure {
        close()
        return TransportSignerOutcome.Failure(error)
    }

    private fun reportQuiescence() {
        if (!isQuiescent()) return
        val notify = synchronized(cleanupLock) {
            if (releaseReported) false else { releaseReported = true; true }
        }
        if (notify) released(this)
    }

    override fun toString(): String = "NativeTransportSigner([redacted], tls_only)"
}
