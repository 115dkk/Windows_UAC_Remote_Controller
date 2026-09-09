// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.background

import android.content.Intent
import java.lang.ref.WeakReference

internal enum class BootComponentState { DEFAULT, ENABLED, DISABLED, UNAVAILABLE }
internal enum class UserUnlockObservation { UNLOCKED, LOCKED, UNAVAILABLE }
internal enum class ServiceControlResult { REQUESTED, DISABLED, UNAVAILABLE }
internal enum class ControllerServiceState { WAITING_FOR_UNLOCK, PREPARING, LOCAL_SETTINGS_READY, CLEANUP_PENDING, UNAVAILABLE, STOPPED }
internal enum class BootOwnerAction { START_NEW, KEEP_EXISTING, WAIT_FOR_UNLOCK, WAIT_FOR_CLEANUP, UNAVAILABLE }

/** Pure admission/shape rules only. No OS start, storage or authentication proof. */
internal object BootServicePolicy {
    const val MAX_PENDING_READS = 8
    const val PRE_OWNER_READ_TIMEOUT_MILLIS = 5_000L

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
