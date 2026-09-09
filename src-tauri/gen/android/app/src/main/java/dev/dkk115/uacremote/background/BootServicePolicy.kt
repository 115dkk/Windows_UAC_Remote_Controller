// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.background

import android.content.Intent
import java.lang.ref.WeakReference

internal enum class BootComponentState { DEFAULT, ENABLED, DISABLED, UNAVAILABLE }
internal enum class UserUnlockObservation { UNLOCKED, LOCKED, UNAVAILABLE }
internal enum class ServiceControlResult(val wireValue: String) {
    REQUESTED("requested"), DISABLED("not_allowed"), NOT_ALLOWED("not_allowed"), UNAVAILABLE("unavailable"),
}
internal enum class ControllerServiceState(val wireValue: String) {
    WAITING_FOR_UNLOCK("waiting_for_unlock"), PREPARING("preparing"),
    LOCAL_SETTINGS_READY("local_settings_ready"), CLEANUP_PENDING("cleanup_pending"),
    UNAVAILABLE("unavailable"), STOPPED("stopped"),
}
internal enum class BootOwnerAction { START_NEW, KEEP_EXISTING, WAIT_FOR_UNLOCK, WAIT_FOR_CLEANUP, UNAVAILABLE }
internal enum class NativeStopObservation { MATCHED_SERVICE, NOT_RUNNING }

/** Process-local start identities only. No reset/wrap and no renderer input. */
internal class ServiceStartGenerations(initialNext: Long = 1L) {
    private var next: Long? = initialNext.also { require(it > 0) }
    private var current: Long? = null
    fun reserve(): Long? {
        val value = next ?: return null
        next = if (value == Long.MAX_VALUE) null else value + 1
        current = value
        return value
    }
    fun current(): Long? = current
    fun canReserve(): Boolean = next != null
    fun matches(value: Long?): Boolean = value != null && value > 0 && current == value
    fun invalidate() { current = null }
    override fun toString(): String = "ServiceStartGenerations(process_local)"
}

/** Snapshot only. These fields are assembled from native owners, not IPC flags. */
internal data class ControllerServiceFacts(
    val component: BootComponentState,
    val reportedState: ControllerServiceState,
    val wanted: Boolean,
    val attached: Boolean,
    val startPending: Boolean,
    val phase: PolicyOwnerPhase?,
    val constructionUncertain: Boolean,
    val startRejected: Boolean,
    val generationAvailable: Boolean,
)

internal data class ControllerServiceObservation(
    val state: ControllerServiceState,
    val bootEnabled: Boolean?,
    val canStart: Boolean,
    val canStop: Boolean,
    val policyOwnerReady: Boolean,
) {
    companion object {
        val UNAVAILABLE = ControllerServiceObservation(ControllerServiceState.UNAVAILABLE, null, false, false, false)
    }
}

/** Pure admission/shape rules only. No OS start, storage or authentication proof. */
internal object BootServicePolicy {
    const val MAX_PENDING_READS = 8
    const val PRE_OWNER_READ_TIMEOUT_MILLIS = 5_000L
    const val MAX_SERVICE_ARGUMENT_CHARS = 32
    const val SERVICE_COMMAND_TIMEOUT_MILLIS = 5_000L

    fun bootEnabled(state: BootComponentState): Boolean = state == BootComponentState.DEFAULT || state == BootComponentState.ENABLED

    fun acceptsBootAction(action: String?): Boolean = action == Intent.ACTION_LOCKED_BOOT_COMPLETED ||
        action == Intent.ACTION_BOOT_COMPLETED || action == Intent.ACTION_MY_PACKAGE_REPLACED

    fun ownerAction(
        unlocked: UserUnlockObservation,
        current: PolicyOwnerPhase?,
        mayReplaceClosed: Boolean,
        constructionUncertain: Boolean,
    ): BootOwnerAction = when {
        unlocked == UserUnlockObservation.LOCKED -> BootOwnerAction.WAIT_FOR_UNLOCK
        unlocked != UserUnlockObservation.UNLOCKED || constructionUncertain -> BootOwnerAction.UNAVAILABLE
        current == null -> BootOwnerAction.START_NEW
        current == PolicyOwnerPhase.CLOSED -> if (mayReplaceClosed) BootOwnerAction.START_NEW else BootOwnerAction.UNAVAILABLE
        current == PolicyOwnerPhase.FAILED || current == PolicyOwnerPhase.STOPPING -> BootOwnerAction.WAIT_FOR_CLEANUP
        else -> BootOwnerAction.KEEP_EXISTING
    }

    fun canQueueRead(count: Int): Boolean = count in 0 until MAX_PENDING_READS
    fun readExpired(started: Long, now: Long): Boolean = started < 0 || now < started || now - started >= PRE_OWNER_READ_TIMEOUT_MILLIS

    fun acceptsServiceArguments(raw: String): Boolean = raw.length <= MAX_SERVICE_ARGUMENT_CHARS &&
        raw.trim().let { it == "null" || it == "{}" }

    fun serviceCommandExpired(started: Long, now: Long): Boolean =
        started < 0 || now < started || now - started >= SERVICE_COMMAND_TIMEOUT_MILLIS

    fun automaticStartAllowed(facts: ControllerServiceFacts, explicitStopRequested: Boolean, mayReplaceClosed: Boolean): Boolean =
        bootEnabled(facts.component) && facts.generationAvailable && !explicitStopRequested && !facts.startRejected &&
        !facts.constructionUncertain && !facts.startPending && !(facts.attached && !facts.wanted) &&
        facts.phase != PolicyOwnerPhase.FAILED && facts.phase != PolicyOwnerPhase.STOPPING &&
        !(facts.phase == PolicyOwnerPhase.CLOSED && !mayReplaceClosed)

    /** Called only after a real framework null-intent sticky restart. The caller
     * also checks its exact attached Service token before minting a generation. */
    fun stickyStartAllowed(facts: ControllerServiceFacts, explicitStopRequested: Boolean, mayReplaceClosed: Boolean): Boolean =
        bootEnabled(facts.component) && facts.generationAvailable && !explicitStopRequested && !facts.startRejected &&
        !facts.constructionUncertain && facts.phase != PolicyOwnerPhase.FAILED &&
        facts.phase != PolicyOwnerPhase.STOPPING &&
        !(facts.phase == PolicyOwnerPhase.CLOSED && !mayReplaceClosed) &&
        (facts.phase == null || facts.phase == PolicyOwnerPhase.CLOSED || facts.wanted)

    fun acceptsStartGeneration(current: Long?, supplied: Long?, activated: Long?): Boolean =
        supplied != null && supplied > 0 && current == supplied && (activated == null || activated == supplied)

    fun detachOwnsCurrentGeneration(currentToken: Any?, callbackToken: Any, current: Long?, activated: Long?, callback: Long?): Boolean =
        currentToken === callbackToken && callback != null && callback > 0 && current == callback && activated == callback

    fun stopAcknowledgmentClearsPending(currentGeneration: Long?, explicitStopRequested: Boolean, observation: NativeStopObservation): Boolean =
        currentGeneration == null && explicitStopRequested && when (observation) {
            NativeStopObservation.MATCHED_SERVICE, NativeStopObservation.NOT_RUNNING -> true
        }

    fun serviceObservation(facts: ControllerServiceFacts, actualForegroundHost: Boolean): ControllerServiceObservation {
        val boot = when (facts.component) {
            BootComponentState.DEFAULT, BootComponentState.ENABLED -> true
            BootComponentState.DISABLED -> false
            BootComponentState.UNAVAILABLE -> null
        }
        val actorMayLive = facts.phase != null && facts.phase != PolicyOwnerPhase.CLOSED
        val fullyStopped = !facts.wanted && !facts.attached && !facts.startPending &&
            !actorMayLive && !facts.constructionUncertain
        val ready = boot == true && facts.wanted && facts.attached &&
            facts.phase == PolicyOwnerPhase.READY && !facts.startRejected && !facts.constructionUncertain
        val observedState = when {
            facts.constructionUncertain || boot == null -> ControllerServiceState.UNAVAILABLE
            !facts.wanted && (facts.attached || facts.startPending || actorMayLive) -> ControllerServiceState.CLEANUP_PENDING
            facts.phase == PolicyOwnerPhase.STOPPING -> ControllerServiceState.CLEANUP_PENDING
            fullyStopped && boot == false -> ControllerServiceState.STOPPED
            facts.startRejected || facts.phase == PolicyOwnerPhase.FAILED -> ControllerServiceState.UNAVAILABLE
            fullyStopped -> ControllerServiceState.STOPPED
            ready -> ControllerServiceState.LOCAL_SETTINGS_READY
            boot == false -> ControllerServiceState.UNAVAILABLE
            facts.wanted && facts.attached && facts.phase == null &&
                facts.reportedState == ControllerServiceState.WAITING_FOR_UNLOCK -> ControllerServiceState.WAITING_FOR_UNLOCK
            facts.reportedState == ControllerServiceState.UNAVAILABLE -> ControllerServiceState.UNAVAILABLE
            facts.wanted && (facts.attached || facts.startPending || actorMayLive) -> ControllerServiceState.PREPARING
            else -> ControllerServiceState.UNAVAILABLE
        }
        val recoverableStart = boot != null && facts.generationAvailable && !facts.wanted && !facts.attached && !facts.startPending &&
            !actorMayLive && !facts.constructionUncertain &&
            (observedState == ControllerServiceState.STOPPED || observedState == ControllerServiceState.UNAVAILABLE)
        // An unknown PackageManager observation never means disabled. An
        // explicit foreground stop may still attempt both downward operations.
        val stopUseful = boot != false || !fullyStopped
        return ControllerServiceObservation(observedState, boot,
            actualForegroundHost && recoverableStart, actualForegroundHost && stopUseful, ready)
    }
}

/** Identity bookkeeping only; production calls originate in framework callbacks. */
internal class ResumedHostTrace<T : Any> {
    private var host: WeakReference<T>? = null
    @Synchronized fun resumed(actualHost: T) { host = WeakReference(actualHost) }
    @Synchronized fun pausedOrDestroyed(actualHost: Any) {
        if (host?.get() === actualHost) host = null
    }
    @Synchronized fun current(): T? = host?.get()
    override fun toString(): String = "ResumedHostTrace(lifecycle_only)"
}
