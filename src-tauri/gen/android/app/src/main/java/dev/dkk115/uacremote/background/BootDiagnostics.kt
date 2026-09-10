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

/** Observation only: no retained state, files, retries or lifecycle decisions. */
internal object BootDiagnostics {
    const val MAX_LINE_CHARS = 384
    fun record(value: BootDiagnosticRecord) {
        try {
            val line = value.line()
            if (line.length <= MAX_LINE_CHARS) Log.i("UacBoot", line)
        } catch (_: Exception) { /* Diagnostic delivery never changes admission. */ }
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
