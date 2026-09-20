// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.security

internal enum class DenialSigningError {
    WRONG_THREAD, ALREADY_USED, CANCELLED, INVALID_INPUT, EXPIRED, CLOCK_UNAVAILABLE,
    CLOCK_REGRESSED, KEY_UNAVAILABLE, SIGNING_FAILED, CLEANUP_PENDING,
}

internal class DenialSigningException(val reason: DenialSigningError, val keyError: DeviceKeyError? = null) :
    RuntimeException(null, null, false, false)

/** Shape only; the opaque Rust attempt, not this helper, supplies authority. */
internal object DenialSigningPolicy {
    private val domain = "Windows-UAC-Remote-Controller/deny/v1\u0000".toByteArray(Charsets.US_ASCII)
    const val MIN_DER_BYTES = 8
    const val MAX_DER_BYTES = 72
    const val MAX_OPERATIONS = 32
    val statementBytes: Int = domain.size + 199
    fun validStatement(bytes: ByteArray): Boolean = bytes.size == statementBytes &&
        domain.indices.all { bytes[it] == domain[it] } && bytes[domain.size] == 0.toByte() &&
        bytes[domain.size + 1] == 1.toByte() && bytes[domain.size + 18] == 2.toByte()
    fun validDerLength(length: Int): Boolean = length in MIN_DER_BYTES..MAX_DER_BYTES
}

internal class DenialTimeWindow(private val deadline: Long, private var last: Long) {
    fun observe(now: Long): DenialSigningError? = when {
        deadline <= 0 || last < 0 -> DenialSigningError.INVALID_INPUT
        now < 0 -> DenialSigningError.CLOCK_UNAVAILABLE
        now < last -> DenialSigningError.CLOCK_REGRESSED
        now >= deadline -> DenialSigningError.EXPIRED
        else -> { last = now; null }
    }
}

internal enum class DenialOperationObservation { NOT_STARTED, RUNNING, QUIESCENT, FAILED }

/** A failed operation can be cleanly terminal even if no provider call started. */
internal class DenialOperationPolicy {
    private var started = false
    private var running = false
    private var terminal = false
    private var cancelled = false
    private var cleaned = false
    private var cleanupFailed = false
    @Synchronized fun begin(): Boolean {
        if (started || terminal || cancelled) return false
        started = true; running = true
        return true
    }
    @Synchronized fun mayReturn(): Boolean = running && !cancelled
    @Synchronized fun returned() { check(running); running = false; terminal = true }
    @Synchronized fun cancel() { cancelled = true; terminal = true }
    @Synchronized fun mayClean(): Boolean = terminal && !running
    @Synchronized fun cleaned() { check(mayClean() && !cleanupFailed); cleaned = true }
    @Synchronized fun cleanupFailed() { cleanupFailed = true }
    @Synchronized fun retryCleanup() { cleanupFailed = false }
    @Synchronized fun observation(): DenialOperationObservation = when {
        running -> DenialOperationObservation.RUNNING
        cleanupFailed -> DenialOperationObservation.FAILED
        terminal && cleaned -> DenialOperationObservation.QUIESCENT
        !started && !terminal -> DenialOperationObservation.NOT_STARTED
        else -> DenialOperationObservation.RUNNING
    }
    override fun toString(): String = "DenialOperationPolicy(cleanup_only)"
}
