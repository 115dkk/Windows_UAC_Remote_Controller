// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.security

internal enum class TransportSignerError {
    WRONG_THREAD, BUSY, CLOSED, IDENTITY_MISMATCH, INVALID_FRAME,
    KEY_UNAVAILABLE, SIGNING_FAILED, NATIVE_UNAVAILABLE, CLEANUP_PENDING,
}

internal sealed class TransportSignerOutcome<out T> {
    class Value<T>(val value: T) : TransportSignerOutcome<T>()
    class Failure(val error: TransportSignerError, val keyError: DeviceKeyError? = null) : TransportSignerOutcome<Nothing>()
    final override fun toString(): String = when (this) {
        is Value -> "TransportSignerOutcome.Value([redacted])"
        is Failure -> "TransportSignerOutcome.Failure($error, $keyError)"
    }
}

/** Exact process-local registration identity, not SPKI/alias equality or authority. */
internal class TransportReferenceIdentity(private val registration: Any, private val reference: Any) {
    fun matches(currentRegistration: Any, currentReference: Any): Boolean =
        registration === currentRegistration && reference === currentReference
    override fun toString(): String = "TransportReferenceIdentity([redacted])"
}

/** Pure single-flight/cleanup state. It neither owns a key nor authenticates input. */
internal class TransportSignerPolicy {
    private var closed = false
    private var inFlight = false
    @Synchronized fun begin(): TransportSignerError? = when {
        closed -> TransportSignerError.CLOSED
        inFlight -> TransportSignerError.BUSY
        else -> { inFlight = true; null }
    }
    @Synchronized fun completionAllowed(): Boolean = inFlight && !closed
    @Synchronized fun returned() {
        check(inFlight) { "No transport signing call is active" }
        inFlight = false
    }
    @Synchronized fun close() { closed = true }
    @Synchronized fun isQuiescent(): Boolean = closed && !inFlight
    override fun toString(): String = "TransportSignerPolicy(lifetime_only)"
}

/** RFC8446 Client CertificateVerify only. No arbitrary-message/prehash entry. */
internal object ClientCertificateVerifyPolicy {
    private val context = "TLS 1.3, client CertificateVerify".toByteArray(Charsets.US_ASCII)
    private val separator = 64 + context.size
    private val header = separator + 1
    const val MIN_DER_BYTES = 8
    const val MAX_DER_BYTES = 72
    const val MAX_SIGNERS = 32
    fun valid(bytes: ByteArray): Boolean = (bytes.size == header + 32 || bytes.size == header + 48) &&
        (0 until 64).all { bytes[it] == 0x20.toByte() } &&
        context.indices.all { bytes[64 + it] == context[it] } && bytes[separator] == 0.toByte()
    fun validDerLength(length: Int): Boolean = length in MIN_DER_BYTES..MAX_DER_BYTES
}
