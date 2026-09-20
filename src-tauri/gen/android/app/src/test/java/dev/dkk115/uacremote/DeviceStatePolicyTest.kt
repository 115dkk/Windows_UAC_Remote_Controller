// SPDX-License-Identifier: GPL-2.0-or-later

package dev.dkk115.uacremote

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Synthetic mapping probes only: not Android lock, permission or settings QA. */
class DeviceStatePolicyTest {
    @Test
    fun notificationSettingsAreAdvertisedOnlyForDeniedAndResolvableState() {
        for (enabled in listOf<Boolean?>(true, false, null)) {
            for (resolvable in listOf(false, true)) {
                var resolutions = 0
                val observed = observeDeviceReadiness(
                    foreground = true,
                    readSecureLock = { true },
                    readNotificationsEnabled = { enabled },
                    settingsResolvable = { error("configured lock must not resolve settings") },
                    notificationSettingsResolvable = { resolutions += 1; resolvable },
                )
                assertEquals(enabled == false && resolvable, observed.canOpenNotificationSettings)
                assertEquals(if (enabled == false) 1 else 0, resolutions)
                assertFalse(observed.canOpenLockSettings)
            }
        }
    }

    @Test
    fun notificationSettingsResolutionFailureDoesNotInventPermissionState() {
        val observed = observeDeviceReadiness(
            foreground = true,
            readSecureLock = { true },
            readNotificationsEnabled = { false },
            settingsResolvable = { false },
            notificationSettingsResolvable = { throw SecurityException("synthetic resolver failure") },
        )
        assertEquals(NotificationObservation.DENIED, observed.notifications)
        assertFalse(observed.canOpenNotificationSettings)
    }

    @Test
    fun secureLockTrueFalseAndUnavailableHaveDistinctWireValues() {
        assertEquals("configured", readSecureLockObservation { true }.wireValue)
        assertEquals("missing", readSecureLockObservation { false }.wireValue)
        assertEquals("unavailable", readSecureLockObservation { null }.wireValue)
        assertEquals(
            SecureLockObservation.UNAVAILABLE,
            readSecureLockObservation { throw SecurityException("synthetic probe failure") },
        )
    }

    @Test
    fun configuredLockDoesNotResolveOrAdvertiseTheSettingsScreen() {
        var resolutions = 0
        val observed = observeDeviceReadiness(
            foreground = true,
            readSecureLock = { true },
            readNotificationsEnabled = { true },
            settingsResolvable = { resolutions += 1; true },
        )
        assertEquals(SecureLockObservation.CONFIGURED, observed.screenLock)
        assertEquals(NotificationObservation.ALLOWED, observed.notifications)
        assertFalse(observed.canOpenLockSettings)
        assertEquals(0, resolutions)
    }

    @Test
    fun missingLockAdvertisesOnlyAnActuallyResolvableSettingsScreen() {
        for (resolvable in listOf(false, true)) {
            var resolutions = 0
            val observed = observeDeviceReadiness(
                foreground = true,
                readSecureLock = { false },
                readNotificationsEnabled = { false },
                settingsResolvable = { resolutions += 1; resolvable },
            )
            assertEquals(SecureLockObservation.MISSING, observed.screenLock)
            assertEquals(NotificationObservation.DENIED, observed.notifications)
            assertEquals(resolvable, observed.canOpenLockSettings)
            assertEquals(1, resolutions)
        }
    }

    @Test
    fun secureLockReadFailureDoesNotBecomeMissingOrEraseNotificationObservation() {
        var resolutions = 0
        val observed = observeDeviceReadiness(
            foreground = true,
            readSecureLock = { throw IllegalStateException("synthetic unavailable service") },
            readNotificationsEnabled = { true },
            settingsResolvable = { resolutions += 1; true },
        )
        assertEquals(SecureLockObservation.UNAVAILABLE, observed.screenLock)
        assertEquals(NotificationObservation.ALLOWED, observed.notifications)
        assertFalse(observed.canOpenLockSettings)
        assertEquals(0, resolutions)
    }

    @Test
    fun notificationReadFailureDoesNotBecomeDeniedOrChangeTheLockObservation() {
        val observed = observeDeviceReadiness(
            foreground = true,
            readSecureLock = { false },
            readNotificationsEnabled = { throw SecurityException("synthetic unavailable service") },
            settingsResolvable = { true },
        )
        assertEquals(SecureLockObservation.MISSING, observed.screenLock)
        assertEquals(NotificationObservation.UNAVAILABLE, observed.notifications)
        assertTrue(observed.canOpenLockSettings)
    }

    @Test
    fun missingServicesRemainUnavailableRatherThanFalse() {
        val observed = observeDeviceReadiness(
            foreground = true,
            readSecureLock = { null },
            readNotificationsEnabled = { null },
            settingsResolvable = { error("unavailable lock must not query settings") },
        )
        assertEquals(DeviceReadinessObservation.UNAVAILABLE, observed)
    }

    @Test
    fun settingsResolutionFailureOnlyDisablesTheSettingsAction() {
        val observed = observeDeviceReadiness(
            foreground = true,
            readSecureLock = { false },
            readNotificationsEnabled = { false },
            settingsResolvable = { throw SecurityException("synthetic resolver failure") },
        )
        assertEquals(SecureLockObservation.MISSING, observed.screenLock)
        assertEquals(NotificationObservation.DENIED, observed.notifications)
        assertFalse(observed.canOpenLockSettings)
    }

    @Test
    fun backgroundStateDoesNotReadOrLaunchAnything() {
        var probes = 0
        val observed = observeDeviceReadiness(
            foreground = false,
            readSecureLock = { probes += 1; false },
            readNotificationsEnabled = { probes += 1; true },
            settingsResolvable = { probes += 1; true },
            notificationSettingsResolvable = { probes += 1; true },
        )
        assertEquals(DeviceReadinessObservation.UNAVAILABLE, observed)
        assertEquals(0, probes)
    }
}
