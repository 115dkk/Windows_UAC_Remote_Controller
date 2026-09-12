// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.background

import android.app.ForegroundServiceStartNotAllowedException
import android.content.Intent
import android.os.Build
import android.util.Log

internal enum class BootDiagnosticAction { LOCKED_BOOT, BOOT, PACKAGE_REPLACED }
internal enum class BootDiagnosticFailure { SECURITY, BACKGROUND_START, OTHER }
internal enum class BootDiagnosticStage {
    APPLICATION_CREATE, RECEIVER_ACCEPTED, RECEIVER_RESULT, AUTOMATIC_ADMISSION,
    START_REQUESTED, START_REQUEST_FAILED, SERVICE_CREATE, ATTACHMENT_REJECTED,
    PROMOTION_SUCCEEDED, PROMOTION_FAILED, START_COMMAND, COMPONENT_REJECTED,
    GENERATION_ACCEPTED, GENERATION_REJECTED, START_REJECTED_LATCHED,
    UNLOCK_RECEIVER_FAILED, UNLOCK_REFRESH, NOTIFICATION_FAILED, SERVICE_DESTROY,
    ACTIVATION_OBSERVED, ACTIVATION_MUTATION_STARTED, ACTIVATION_MUTATION_FINISHED,
}

/** Fixed metadata only. No text, Intent, exception, identifier or body field. */
internal data class BootDiagnosticRecord(
    val stage: BootDiagnosticStage,
    val action: BootDiagnosticAction? = null,
    val component: BootComponentState? = null,
    val unlock: UserUnlockObservation? = null,
    val result: ServiceControlResult? = null,
    val failure: BootDiagnosticFailure? = null,
    val admitted: Boolean? = null,
    val sticky: Boolean? = null,
    val generationPresent: Boolean? = null,
    val attached: Boolean? = null,
    val promoted: Boolean? = null,
    val keptCurrent: Boolean? = null,
    val activation: BootActivationState? = null,
    val activationPending: Boolean? = null,
    val activationUncertain: Boolean? = null,
) {
    fun line(): String = buildString {
        append("stage=").append(stage.name)
        action?.let { append(" action=").append(it.name) }
        component?.let { append(" component=").append(it.name) }
        unlock?.let { append(" unlock=").append(it.name) }
        result?.let { append(" result=").append(it.name) }
        failure?.let { append(" failure=").append(it.name) }
        admitted?.let { append(" admitted=").append(it) }
        sticky?.let { append(" sticky=").append(it) }
        generationPresent?.let { append(" generation_present=").append(it) }
        attached?.let { append(" attached=").append(it) }
        promoted?.let { append(" promoted=").append(it) }
        keptCurrent?.let { append(" kept_current=").append(it) }
        activation?.let { append(" activation=").append(it.name) }
        activationPending?.let { append(" activation_pending=").append(it) }
        activationUncertain?.let { append(" activation_uncertain=").append(it) }
    }
}

internal enum class OwnerDiagnosticEvent { OWNER_INIT_STEP, OWNER_READY, OWNER_FIRST_FAILURE, OWNER_CLOSED }
internal enum class OwnerInitializationStep { QUEUED, PACKAGED_LIBRARY, GENERATED_CONTRACT, BRIDGE_ABI, OPEN_NATIVE_OWNER, READY }
internal enum class OwnerFailureOrigin {
    INIT_TIMER_POST, INIT_WORKER_SCHEDULE, INIT_WATCHDOG, INIT_PRECHECK, INIT_COMPLETION, INIT_EXCEPTION,
    CALL_TIMER_POST, CALL_TIMEOUT, CALL_WORKER_DEADLINE, CALL_EXCEPTION, CALL_MAIN_DEADLINE, CALL_MAIN_POST,
    REQUEST_MAINTENANCE, APPROVAL_OWNER, DENIAL_OWNER,
}
internal enum class OwnerFailureCategory { NOT_CAPTURED, LINKAGE, SECURITY, STATE_CHECK, OTHER }

/** Closed diagnostic metadata only; no Throwable, native handle or user input. */
internal data class OwnerDiagnosticRecord(
    val event: OwnerDiagnosticEvent,
    val step: OwnerInitializationStep?,
    val phase: PolicyOwnerPhase,
    val origin: OwnerFailureOrigin? = null,
    val category: OwnerFailureCategory? = null,
    val status: PolicyStatus? = null,
) {
    fun line(): String = buildString {
        append("stage=").append(event.name)
        step?.let { append(" owner_step=").append(it.name) }
        append(" owner_phase=").append(phase.name)
        origin?.let { append(" owner_origin=").append(it.name) }
        category?.let { append(" owner_category=").append(it.name) }
        status?.let { append(" owner_status=").append(it.name) }
    }
}

/** Per-actor observation only, not lifecycle admission. No generated/JNA types,
 * clock reads, retries or owner operations. At most five init steps, READY, one first
 * failure and CLOSED. A late timeout/error cannot replace the original reason.
 * The short lock protects only snapshots; delivery is always outside the lock. */
internal class OwnerBootTrace(private val emit: (OwnerDiagnosticRecord) -> Unit) {
    private val lock = Any()
    private var step: OwnerInitializationStep? = null
    private var firstFailure: OwnerDiagnosticRecord? = null
    private var closed = false

    fun initializing(value: OwnerInitializationStep) = observe {
        synchronized(lock) {
            if (closed || firstFailure != null || value == OwnerInitializationStep.READY ||
                (step?.ordinal ?: -1) >= value.ordinal) null
            else {
                step = value
                OwnerDiagnosticRecord(OwnerDiagnosticEvent.OWNER_INIT_STEP, step, PolicyOwnerPhase.STARTING)
            }
        }
    }

    /** Called only after the real lifecycle accepted initialization. */
    fun ready() = observe {
        synchronized(lock) {
            if (closed || firstFailure != null || step != OwnerInitializationStep.OPEN_NATIVE_OWNER) null
            else {
                step = OwnerInitializationStep.READY
                OwnerDiagnosticRecord(OwnerDiagnosticEvent.OWNER_READY, step, PolicyOwnerPhase.READY)
            }
        }
    }

    fun failed(origin: OwnerFailureOrigin, category: OwnerFailureCategory, status: PolicyStatus, phase: PolicyOwnerPhase) = observe {
        synchronized(lock) {
            if (closed || firstFailure != null) null
            else OwnerDiagnosticRecord(OwnerDiagnosticEvent.OWNER_FIRST_FAILURE, step, phase, origin, category, status)
                .also { firstFailure = it }
        }
    }

    /** Called only at the existing actual terminal-cleanup publication. */
    fun closed() = observe {
        synchronized(lock) {
            if (closed) null
            else {
                closed = true
                val original = firstFailure
                OwnerDiagnosticRecord(OwnerDiagnosticEvent.OWNER_CLOSED, step, PolicyOwnerPhase.CLOSED,
                    original?.origin, original?.category, original?.status)
            }
        }
    }

    private fun observe(snapshot: () -> OwnerDiagnosticRecord?) {
        try { snapshot()?.let(emit) }
        catch (_: Throwable) {
            // Only diagnostic work is inside this boundary. An unavailable
            // logger/formatter must not alter real failure handling or cleanup.
        }
    }
}

/** Observation only: no retained state, files, retries or lifecycle decisions. */
internal object BootDiagnostics {
    const val MAX_LINE_CHARS = 384
    /** Only called during generated contract registration, before opening any
     * app state/keys. Never emit Throwable text, paths, arguments or addresses. */
    internal fun contractLinkageLines(failure: Throwable): List<String> {
        val lines = ArrayList<String>()
        var current: Throwable? = failure
        repeat(4) { depth ->
            val value = current ?: return lines
            val kind = when (value) {
                is ExceptionInInitializerError -> "INITIALIZER"
                is UnsatisfiedLinkError -> "UNSATISFIED_LINK"
                is NoClassDefFoundError -> "CLASS_MISSING"
                is NoSuchMethodError -> "METHOD_MISSING"
                is NoSuchFieldError -> "FIELD_MISSING"
                is IllegalArgumentException -> "ARGUMENT"
                is IllegalStateException -> "STATE"
                is RuntimeException -> "RUNTIME"
                else -> "OTHER"
            }
            val text = value.message.orEmpty()
            val reason = when {
                text.contains("UniFFI contract version mismatch") -> "CONTRACT_VERSION"
                text.contains("UniFFI API checksum mismatch") -> "API_CHECKSUM"
                text.contains("Unable to load library") -> "LIBRARY_LOAD"
                text.contains("Error looking up function") || text.contains("undefined symbol") -> "SYMBOL_LOOKUP"
                text.contains("Structure") || text.contains("field order") || text.contains("newInstance") -> "STRUCTURE"
                text.contains("native library", ignoreCase = true) && text.contains("incompatible", ignoreCase = true) -> "NATIVE_VERSION"
                else -> "OTHER"
            }
            val frame = value.stackTrace.firstOrNull {
                it.className.startsWith("com.sun.jna.") || it.className.startsWith("dev.dkk115.uacremote.nativecore.")
            }
            val candidate = frame?.let { "${it.className}.${it.methodName}:${it.lineNumber}" }.orEmpty()
            val site = if (candidate.length in 1..180 && candidate.all { it.isLetterOrDigit() && it.code < 128 || it in ".$_<>:-" }) candidate else "unknown"
            lines.add("stage=CONTRACT_LINKAGE depth=$depth kind=$kind reason=$reason site=$site")
            current = if (value is ExceptionInInitializerError) value.exception ?: value.cause else value.cause
            if (current === value) return lines
        }
        return lines
    }
    internal fun recordContractLinkage(failure: Throwable) {
        try { for (line in contractLinkageLines(failure)) if (line.length <= MAX_LINE_CHARS) Log.i("UacBoot", line) }
        catch (_: Throwable) { /* Diagnostics never change failure handling. */ }
    }
    fun record(value: BootDiagnosticRecord) {
        try {
            val line = value.line()
            if (line.length <= MAX_LINE_CHARS) Log.i("UacBoot", line)
        } catch (_: Exception) { /* Diagnostic delivery never changes admission. */ }
    }

    fun recordOwner(value: OwnerDiagnosticRecord) {
        try {
            val line = value.line()
            if (line.length <= MAX_LINE_CHARS) Log.i("UacBoot", line)
        } catch (_: Throwable) { /* This diagnostic never changes owner decisions. */ }
    }

    /** Type tests only. Never read message, cause, stack, class name or toString. */
    fun ownerFailureCategory(failure: Throwable?): OwnerFailureCategory = when (failure) {
        null -> OwnerFailureCategory.NOT_CAPTURED
        is LinkageError -> OwnerFailureCategory.LINKAGE
        is SecurityException -> OwnerFailureCategory.SECURITY
        is IllegalStateException -> OwnerFailureCategory.STATE_CHECK
        else -> OwnerFailureCategory.OTHER
    }

    fun bootAction(action: String?): BootDiagnosticAction? = when (action) {
        Intent.ACTION_LOCKED_BOOT_COMPLETED -> BootDiagnosticAction.LOCKED_BOOT
        Intent.ACTION_BOOT_COMPLETED -> BootDiagnosticAction.BOOT
        Intent.ACTION_MY_PACKAGE_REPLACED -> BootDiagnosticAction.PACKAGE_REPLACED
        else -> null
    }

    fun failureCategory(failure: Exception): BootDiagnosticFailure = when {
        failure is SecurityException -> BootDiagnosticFailure.SECURITY
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.S && failure is ForegroundServiceStartNotAllowedException -> BootDiagnosticFailure.BACKGROUND_START
        else -> BootDiagnosticFailure.OTHER
    }
}
