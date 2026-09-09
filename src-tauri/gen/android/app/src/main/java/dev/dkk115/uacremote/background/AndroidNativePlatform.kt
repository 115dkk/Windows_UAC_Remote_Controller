// SPDX-License-Identifier: GPL-2.0-or-later

package dev.dkk115.uacremote.background

import android.app.Application
import android.app.NotificationManager
import android.os.Looper
import dev.dkk115.uacremote.nativecore.BridgeException
import dev.dkk115.uacremote.nativecore.NativeClock
import dev.dkk115.uacremote.nativecore.NativePlatform
import dev.dkk115.uacremote.nativecore.NativeLocalKeySet
import dev.dkk115.uacremote.security.DeviceKeyStore
import dev.dkk115.uacremote.security.KeyStoreOutcome
import dev.dkk115.uacremote.security.ReopenKeySetDescriptor

/**
 * Generated-trait adapter only. The Application owner calls it from a bounded
 * background worker. No Activity, app startup, enrollment, permission request,
 * notification posting or authentication takes place at construction.
 */
internal class AndroidNativePlatform(application: Application) : NativePlatform {
    private val application = application
    private val environment = NativeEnvironment(application)
    private val legacy = LegacyPolicyObservation(application)
    private val keyStore = DeviceKeyStore(application)

    override fun legacyPolicyDocument(): String? = legacy.legacyPolicyDocument()
    override fun hasDeviceKeys(): Boolean = legacy.hasDeviceKeys()

    override fun reopenLocalKeySets(keys: List<NativeLocalKeySet>) {
        if (Looper.myLooper() == Looper.getMainLooper() || keys.isEmpty() || keys.size > 32) {
            throw BridgeException.LocalKeysUnavailable()
        }
        // This is committed LOCAL metadata, not paired-device authorization.
        // Copy/validate the whole tuple list before any reference publication.
        val descriptors = keys.map { key ->
            keyValue(ReopenKeySetDescriptor.fromTrustedStorage(
                key.handle, key.approvalSpki, key.denialSpki, key.transportSpki,
            ))
        }
        val handles = descriptors.map { it.copyHandle() }
        try {
            keyValue(keyStore.validateRecordedNamespace(handles))
            for (descriptor in descriptors) keyValue(keyStore.reopenExistingKeySet(descriptor))
            keyValue(keyStore.validateRecordedNamespace(handles))
        } catch (_: Exception) {
            // Close this adapter's references only. A failed close remains
            // retryable through the Application-retained adapter; never touch
            // aliases/snapshot bytes or an unrelated instance's registrations.
            keyStore.closeReferences()
            throw BridgeException.LocalKeysUnavailable()
        }
    }

    override fun releaseLocalKeyReferences() {
        keyValue(keyStore.closeReferences())
    }

    private fun <T> keyValue(result: KeyStoreOutcome<T>): T = when (result) {
        is KeyStoreOutcome.Value -> result.value
        is KeyStoreOutcome.Failure -> throw BridgeException.LocalKeysUnavailable()
    }

    override fun unixMillis(): ULong {
        if (Looper.myLooper() == Looper.getMainLooper()) throw BridgeException.NativeUnavailable()
        val observed = System.currentTimeMillis()
        if (observed < 0) throw BridgeException.NativeUnavailable()
        // Actual phone display/retention time only. Rust validates its range;
        // authorization and expiry use the separate elapsedRealtimeNanos clock.
        return observed.toULong()
    }

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
