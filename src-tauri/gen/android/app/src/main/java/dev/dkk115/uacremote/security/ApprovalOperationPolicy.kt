// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.security

import android.hardware.biometrics.BiometricManager

/** Fixed native categories; never Android/provider messages, credentials or DER. */
internal enum class ApprovalOperationError {
    BUSY, WRONG_THREAD, INVALID_PLAN, EXPIRED, CLOCK_UNAVAILABLE, CLOCK_REGRESSED,
    CANCELLED, ALREADY_USED, HOST_UNAVAILABLE, HOST_CHANGED,
    AUTHENTICATION_UNAVAILABLE, AUTHENTICATION_CANCELLED, AUTHENTICATION_ERROR,
    CRYPTO_OBJECT_MISMATCH, KEYS_UNAVAILABLE, INVALID_SIGNING_INPUT, SIGNING_FAILED,
    NATIVE_UNAVAILABLE, CLEANUP_PENDING,
}

internal sealed class ApprovalOperationOutcome<out T> {
    class Value<T>(val value: T) : ApprovalOperationOutcome<T>()
    class Failure(
        val error: ApprovalOperationError,
        val keyError: DeviceKeyError? = null,
    ) : ApprovalOperationOutcome<Nothing>()

    final override fun toString(): String = when (this) {
        is Value -> "ApprovalOperationOutcome.Value([redacted])"
        is Failure -> "ApprovalOperationOutcome.Failure($error, $keyError)"
    }
}

/**
 * Pure one-shot bookkeeping, NOT an authentication implementation. Production
 * keeps this instance private inside the real CryptoObject holder; only that
 * holder's actual BiometricPrompt callback calls authenticated(). Tests pass
 * synthetic identity objects and do not construct Android authentication objects.
 */
internal class ApprovalOperationPolicy(
    private val deadlineNanos: Long,
    startedNanos: Long,
    signatureIdentity: Any,
) {
    private enum class Phase { PREPARED, PRESENTING, AUTHENTICATED, SIGNING, TERMINAL }
    private var phase = Phase.PREPARED
    private var lastNanos = startedNanos
    private var signatureIdentity: Any? = signatureIdentity
    private var hostIdentity: Any? = null
    private var inFlight = false
    private var failure: ApprovalOperationError? = null

    init {
        require(startedNanos >= 0 && deadlineNanos > startedNanos) { "Invalid native approval lifetime" }
    }

    @Synchronized fun present(host: Any, now: Long): ApprovalOperationError? {
        if (phase != Phase.PREPARED) return failure ?: ApprovalOperationError.ALREADY_USED
        observe(now)?.let { return it }
        hostIdentity = host
        phase = Phase.PRESENTING
        return null
    }

    @Synchronized fun authenticated(host: Any, returnedSignature: Any?, now: Long): ApprovalOperationError? {
        if (phase != Phase.PRESENTING) return failure ?: ApprovalOperationError.ALREADY_USED
        observe(now)?.let { return it }
        if (hostIdentity !== host) return terminate(ApprovalOperationError.HOST_CHANGED)
        if (returnedSignature == null || returnedSignature !== signatureIdentity) {
            return terminate(ApprovalOperationError.CRYPTO_OBJECT_MISMATCH)
        }
        phase = Phase.AUTHENTICATED
        return null
    }

    @Synchronized fun presentationCheck(now: Long): ApprovalOperationError? {
        if (phase != Phase.PRESENTING) return failure ?: ApprovalOperationError.ALREADY_USED
        return observe(now)
    }

    @Synchronized fun beginSigning(now: Long): ApprovalOperationError? {
        if (phase != Phase.AUTHENTICATED) return failure ?: ApprovalOperationError.ALREADY_USED
        observe(now)?.let { return it }
        inFlight = true
        phase = Phase.SIGNING
        return null
    }

    /** Recheck after potentially blocking key/FFI work and immediately before use. */
    @Synchronized fun signingCheck(now: Long): ApprovalOperationError? {
        if (phase != Phase.SIGNING || !inFlight) return failure ?: ApprovalOperationError.ALREADY_USED
        return observe(now)
    }

    /** Only called after the one native sign invocation has actually returned. */
    @Synchronized fun finishSigning(now: Long): ApprovalOperationError? {
        if (!inFlight) return failure ?: ApprovalOperationError.ALREADY_USED
        val result = if (phase == Phase.SIGNING) observe(now) else failure ?: ApprovalOperationError.ALREADY_USED
        inFlight = false
        phase = Phase.TERMINAL
        signatureIdentity = null
        hostIdentity = null
        return result
    }

    /** Exception/failure exit is also an actual return, not CancellationSignal proof. */
    @Synchronized fun signingExited() {
        inFlight = false
        if (phase != Phase.TERMINAL) terminate(ApprovalOperationError.SIGNING_FAILED)
        signatureIdentity = null
        hostIdentity = null
    }

    @Synchronized fun cancel(reason: ApprovalOperationError = ApprovalOperationError.CANCELLED): ApprovalOperationError =
        terminate(reason)

    @Synchronized fun terminalError(): ApprovalOperationError? = failure
    @Synchronized fun isPrepared(): Boolean = phase == Phase.PREPARED
    @Synchronized fun isAwaitingAuthentication(): Boolean = phase == Phase.PRESENTING
    @Synchronized fun isAwaitingSigning(): Boolean = phase == Phase.AUTHENTICATED
    @Synchronized fun isTerminal(): Boolean = phase == Phase.TERMINAL
    @Synchronized fun isQuiescent(): Boolean = phase == Phase.TERMINAL && !inFlight

    private fun observe(now: Long): ApprovalOperationError? {
        if (now < 0) return terminate(ApprovalOperationError.CLOCK_UNAVAILABLE)
        if (now < lastNanos) return terminate(ApprovalOperationError.CLOCK_REGRESSED)
        lastNanos = now
        if (now >= deadlineNanos) return terminate(ApprovalOperationError.EXPIRED)
        return null
    }

    private fun terminate(reason: ApprovalOperationError): ApprovalOperationError {
        if (failure == null) failure = reason
        phase = Phase.TERMINAL
        // inFlight deliberately remains set until the worker leaves native code.
        signatureIdentity = null
        hostIdentity = null
        return failure ?: reason
    }

    override fun toString(): String = "ApprovalOperationPolicy([redacted])"
}

/** Framing/bounds only. The opaque Rust attempt supplies and verifies authority. */
internal object ApprovalOperationBounds {
    const val ALLOWED_AUTHENTICATORS: Int =
        BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL
    const val MIN_DER_BYTES = 8
    const val MAX_DER_BYTES = 72
    private val approvalDomain = "Windows-UAC-Remote-Controller/approve/v1\u0000".toByteArray(Charsets.US_ASCII)
    private const val UNSIGNED_BYTES = 2 + 16 + 1 + 180
    val signingBytes: Int = approvalDomain.size + UNSIGNED_BYTES

    fun validSigningBytes(bytes: ByteArray): Boolean = bytes.size == signingBytes &&
        approvalDomain.indices.all { bytes[it] == approvalDomain[it] } &&
        bytes[approvalDomain.size] == 0.toByte() && bytes[approvalDomain.size + 1] == 1.toByte() &&
        bytes[approvalDomain.size + 2 + 16] == 1.toByte()

    fun validDerLength(length: Int): Boolean = length in MIN_DER_BYTES..MAX_DER_BYTES
    fun authenticationAvailable(result: Int?): Boolean = result == BiometricManager.BIOMETRIC_SUCCESS
}
