// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.background

internal enum class PolicyStatus(val wireValue: String) {
    BUSY("busy"), UNAVAILABLE("unavailable"), INVALID_POLICY("invalid_policy"),
    STORAGE_UNAVAILABLE("storage_unavailable"),
    HISTORY_UNAVAILABLE("history_unavailable"),
}

internal sealed class PolicyReply {
    class Committed(val policyJson: String) : PolicyReply()
    class HistoryCommitted(val historyJson: String) : PolicyReply()
    class Failed(val status: PolicyStatus) : PolicyReply()
    final override fun toString(): String = when (this) {
        is Committed -> "PolicyReply.Committed([redacted])"
        is HistoryCommitted -> "PolicyReply.HistoryCommitted([redacted])"
        is Failed -> "PolicyReply.Failed($status)"
    }
}

internal object PolicyOwnerBounds {
    const val MAX_POLICY_BYTES = 16 * 1024
    const val MAX_HISTORY_BYTES = 128 * 1024
    const val MAX_RAW_ARGUMENT_CHARS = MAX_POLICY_BYTES * 6 + 128
    const val MAX_PENDING = 8
    const val RESPONSE_TIMEOUT_MILLIS = 15_000L
    const val KEY_NAMESPACE = "dev.dkk115.uacremote.keystore.v1."
    const val MAX_KEY_ALIASES = 4096

    /** Strict scalar/UTF-8 size check without allocating an unbounded byte copy. */
    fun validPolicyString(value: String): Boolean = validBoundedString(value, MAX_POLICY_BYTES)
    fun validHistoryString(value: String): Boolean = validBoundedString(value, MAX_HISTORY_BYTES)

    private fun validBoundedString(value: String, maximum: Int): Boolean {
        if (value.isEmpty() || value.length > maximum) return false
        var bytes = 0
        var index = 0
        while (index < value.length) {
            val char = value[index]
            bytes += when {
                char.code < 0x80 -> 1
                char.code < 0x800 -> 2
                Character.isHighSurrogate(char) -> {
                    if (index + 1 >= value.length || !Character.isLowSurrogate(value[index + 1])) return false
                    index += 1
                    4
                }
                Character.isLowSurrogate(char) -> return false
                else -> 3
            }
            if (bytes > maximum) return false
            index += 1
        }
        return true
    }

    fun responseExpired(startedMillis: Long, nowMillis: Long): Boolean =
        startedMillis < 0 || nowMillis < startedMillis || nowMillis - startedMillis >= RESPONSE_TIMEOUT_MILLIS
}

internal enum class PolicyOwnerPhase { NEW, STARTING, READY, FAILED, STOPPING, CLOSED }

internal enum class ControllerCleanupAction { NONE, SHUTDOWN_THEN_DESTROY, DESTROY }

/** Memory-key cleanup also exists when a Rust constructor returned no handle. */
internal class KeyReferenceCleanupState {
    private var done = false
    private var retryRequired = false
    fun complete(): Boolean = done
    fun shouldAttempt(explicitRetry: Boolean): Boolean = !done && (!retryRequired || explicitRetry)
    fun succeeded() { done = true; retryRequired = false }
    fun failed() { if (!done) retryRequired = true }
    override fun toString(): String = "KeyReferenceCleanupState(owner_scoped)"
}

/** Worker-owned cleanup obligation. A failed shutdown never authorizes destroy. */
internal class ControllerCleanupState {
    private var shutdownAcknowledged = false
    private var blocked = false
    private var destroyed = false
    fun next(explicitRetry: Boolean): ControllerCleanupAction = when {
        destroyed || (blocked && !explicitRetry) -> ControllerCleanupAction.NONE
        shutdownAcknowledged -> ControllerCleanupAction.DESTROY
        else -> ControllerCleanupAction.SHUTDOWN_THEN_DESTROY
    }
    fun shutdownSucceeded() { shutdownAcknowledged = true; blocked = false }
    fun failed() { blocked = true }
    fun destroyed() { destroyed = true; blocked = false }
}

/** Pure, bounded admission/lifecycle state. No native object or settings live here. */
internal class PolicyOwnerLifecycle {
    private var phase = PolicyOwnerPhase.NEW
    private var pending = 0
    private var failure = PolicyStatus.UNAVAILABLE

    @Synchronized fun start(): Boolean {
        if (phase != PolicyOwnerPhase.NEW) return false
        phase = PolicyOwnerPhase.STARTING
        return true
    }

    @Synchronized fun initialized(startedMillis: Long, nowMillis: Long): Boolean {
        if (phase != PolicyOwnerPhase.STARTING) return false
        if (PolicyOwnerBounds.responseExpired(startedMillis, nowMillis)) {
            phase = PolicyOwnerPhase.FAILED
            failure = PolicyStatus.UNAVAILABLE
            return false
        }
        phase = PolicyOwnerPhase.READY
        return true
    }

    @Synchronized fun admit(): PolicyStatus? {
        if (phase != PolicyOwnerPhase.STARTING && phase != PolicyOwnerPhase.READY) return failure
        if (pending >= PolicyOwnerBounds.MAX_PENDING) return PolicyStatus.BUSY
        pending += 1
        return null
    }

    @Synchronized fun release() { check(pending > 0); pending -= 1 }
    @Synchronized fun fail(status: PolicyStatus) {
        if (phase != PolicyOwnerPhase.CLOSED && phase != PolicyOwnerPhase.STOPPING) {
            phase = PolicyOwnerPhase.FAILED
            failure = status
        }
    }
    @Synchronized fun stop() { if (phase != PolicyOwnerPhase.CLOSED) phase = PolicyOwnerPhase.STOPPING }
    @Synchronized fun closed() { phase = PolicyOwnerPhase.CLOSED }
    @Synchronized fun phase(): PolicyOwnerPhase = phase
    @Synchronized fun failure(): PolicyStatus = failure
    @Synchronized fun pendingCount(): Int = pending
    override fun toString(): String = "PolicyOwnerLifecycle(bounded_native_owner)"
}

/** Only property names are inspected; values are never logged or used as paths. */
internal object ControllerLibraryPolicy {
    const val LIBRARY = "uac_android_controller"
    const val ABI_VERSION = 6u

    fun permitsInitialProperties(names: Iterable<String>): Boolean {
        var count = 0
        for (name in names) {
            count += 1
            if (count > 1024 || name.length > 256 || name.isEmpty()) return false
            if (name.startsWith("jna.") || name.startsWith("jnidispatch.") ||
                name.startsWith("uniffi.component.") || name == "javawebstart.version") return false
        }
        return true
    }

    fun isControllerAlias(alias: String): Boolean = alias.startsWith(PolicyOwnerBounds.KEY_NAMESPACE)
}
