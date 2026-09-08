// SPDX-License-Identifier: GPL-2.0-or-later

package dev.dkk115.uacremote.background

import android.app.Application
import android.app.NotificationManager
import android.os.Looper
import dev.dkk115.uacremote.nativecore.BridgeException
import dev.dkk115.uacremote.nativecore.NativeClock
import dev.dkk115.uacremote.nativecore.NativePlatform

/**
 * Generated-trait adapter only. The Application owner calls it from a bounded
 * background worker. No Activity, app startup, enrollment, permission request,
 * notification posting or authentication takes place at construction.
 */
internal class AndroidNativePlatform(application: Application) : NativePlatform {
    private val application = application
    private val environment = NativeEnvironment(application)
    private val legacy = LegacyPolicyObservation(application)

    override fun legacyPolicyDocument(): String? = legacy.legacyPolicyDocument()
    override fun hasDeviceKeys(): Boolean = legacy.hasDeviceKeys()

    override fun stateDirectory(): String = when (val result = environment.controllerDirectory()) {
        is NativeEnvironmentOutcome.Value -> result.value.canonicalPath
        is NativeEnvironmentOutcome.Failure -> throw BridgeException.NativeUnavailable()
    }

    override fun clock(): NativeClock {
        val observed = when (val result = environment.observe()) {
            is NativeEnvironmentOutcome.Value -> result.value
            is NativeEnvironmentOutcome.Failure -> throw BridgeException.NativeUnavailable()
        }
        if (observed.credentialStorage != CredentialStorageState.AVAILABLE) {
            throw BridgeException.NativeUnavailable()
        }
        // Values have already passed native shape/coherence checks. Rust checks
        // them again and owns all schedule/expiry/recovery decisions. This sample
        // is not a post-I/O action permit; native dispatch must observe time again.
        return NativeClock(
            bootCount = observed.bootCount.toUInt(),
            monotonicNanos = observed.elapsedRealtimeNanos.toULong(),
            weekday = observed.weekdayMondayZero.toUByte(),
            minute = observed.minuteOfDay.toUShort(),
        )
    }

    override fun clearRequestNotifications() {
        if (Looper.myLooper() == Looper.getMainLooper()) throw BridgeException.NativeUnavailable()
        try {
            val manager = application.getSystemService(NotificationManager::class.java)
                ?: throw BridgeException.NativeUnavailable()
            for (notification in manager.activeNotifications) {
                if (notification.packageName == application.packageName &&
                    notification.notification.channelId == REQUEST_CHANNEL &&
                    notification.tag?.startsWith(REQUEST_TAG_PREFIX) == true) {
                    manager.cancel(notification.tag, notification.id)
                }
            }
        } catch (_: Exception) {
            // No raw Android exception/path/provider message crosses UniFFI.
            throw BridgeException.NativeUnavailable()
        }
    }

    override fun toString(): String = "AndroidNativePlatform(application_background_adapter)"

    private companion object {
        // Internal ownership namespace, never a user-facing channel label.
        const val REQUEST_CHANNEL = "uac_requests"
        const val REQUEST_TAG_PREFIX = "request:"
    }
}
