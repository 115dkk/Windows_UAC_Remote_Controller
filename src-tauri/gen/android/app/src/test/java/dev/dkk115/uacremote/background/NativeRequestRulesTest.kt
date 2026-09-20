// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.background

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Pure synthetic selectors/caches; no native handles, intents or signing. */
class NativeRequestRulesTest {
    private val locator = "1234567890abcdef".repeat(2)
    private val key = listOf("01".repeat(32), "02".repeat(32), "03".repeat(32)).joinToString(":")
    @Test fun locatorAcceptsOnlyExactLowercase32Hex() {
        assertTrue(NativeRequestRules.locator(locator))
        assertFalse(NativeRequestRules.locator(locator.uppercase()))
        assertFalse(NativeRequestRules.locator(locator.drop(1)))
        assertFalse(NativeRequestRules.locator(locator + "0"))
        assertFalse(NativeRequestRules.locator("/".repeat(32)))
    }
    @Test fun FullSelectionHasThreeSeparateExactComponents() {
        assertTrue(NativeRequestRules.fullKey(key))
        assertFalse(NativeRequestRules.fullKey(key.replace(":", "")))
        assertFalse(NativeRequestRules.fullKey(key.replaceFirst(":", "/")))
        assertFalse(NativeRequestRules.fullKey(key + ":"))
    }
    @Test fun ContentOpenNeverSelectsApproval() {
        val result = NativeRequestRules.routeParts(key, locator, "open")!!
        assertEquals(NativeRequestAction.DETAILS, result.action)
        assertEquals("request:$key", result.key)
        assertEquals(locator, result.locator)
        assertEquals(NativeRequestAction.APPROVE, NativeRequestRules.routeParts(key, locator, "approve")!!.action)
        assertEquals(NativeRequestAction.DENY, NativeRequestRules.routeParts(key, locator, "deny")!!.action)
        assertNull(NativeRequestRules.routeParts(key, locator, "authenticated"))
        assertNull(NativeRequestRules.routeParts(key, locator, "APPROVE"))
        assertNull(NativeRequestRules.routeParts(key.drop(1), locator, "deny"))
    }
    @Test fun OriginalRemainingTimeIsCeiledWithoutExtendingTheDeadline() {
        assertEquals(1L, NativeRequestRules.remainingSeconds(1u, 0u))
        assertEquals(1L, NativeRequestRules.remainingSeconds(1_000_000_000u, 0u))
        assertEquals(2L, NativeRequestRules.remainingSeconds(1_000_000_001u, 0u))
        assertEquals(300L, NativeRequestRules.remainingSeconds(300_000_000_000u, 0u))
        assertEquals(0L, NativeRequestRules.remainingSeconds(5u, 5u))
        assertEquals(0L, NativeRequestRules.remainingSeconds(5u, 6u))
    }
    @Test(expected = IllegalArgumentException::class) fun LifetimeAboveBoundIsNotClampedToSuccess() {
        NativeRequestRules.remainingSeconds(300_000_000_001u, 0u)
    }
    @Test fun DisplayRefreshRoundsDownAndNeverAddsAMinute() {
        assertEquals(0L, NativeRequestRules.refreshMillis(999_999u, 0u))
        assertEquals(1L, NativeRequestRules.refreshMillis(1_000_000u, 0u))
        assertEquals(0L, NativeRequestRules.refreshMillis(1u, 1u))
        assertEquals(60_000L, NativeRequestRules.refreshMillis(61_000_000_000u, 0u))
    }
    @Test fun QueuedDisplayRejectsChangedOwnerCacheEpochExpiryAndStop() {
        fun valid(stopped: Boolean = false, failed: Boolean = false, invalid: Boolean = false,
                  generation: Long = 4, epoch: ULong = 2u, now: ULong = 9u) =
            NativeRequestRules.displayCurrent(stopped, failed, invalid, 4, generation, 2u, epoch, 10u, now)
        assertTrue(valid())
        assertFalse(valid(stopped = true)); assertFalse(valid(failed = true)); assertFalse(valid(invalid = true))
        assertFalse(valid(generation = 5)); assertFalse(valid(epoch = 3u)); assertFalse(valid(now = 10u))
    }
    @Test fun StorageAndHandleBudgetsAreExplicit() {
        assertEquals(32, NativeRequestRules.MAX_REQUESTS)
        assertEquals(64, NativeRequestRules.MAX_HANDLES)
        assertEquals(512 * 1024, NativeRequestRules.MAX_LIST_JSON)
        assertEquals(2 * 1024 * 1024, NativeRequestRules.MAX_DETAILS_JSON)
    }
    @Test fun RecreationColdOwnerAndDenialCannotLaunchActivityApproval() {
        assertTrue(NativeRequestRules.mayRouteActivity(false, true, NativeRequestAction.APPROVE))
        assertTrue(NativeRequestRules.mayRouteActivity(false, true, NativeRequestAction.DETAILS))
        assertFalse(NativeRequestRules.mayRouteActivity(true, true, NativeRequestAction.APPROVE))
        assertFalse(NativeRequestRules.mayRouteActivity(false, false, NativeRequestAction.APPROVE))
        assertFalse(NativeRequestRules.mayRouteActivity(false, true, NativeRequestAction.DENY))
    }
    @Test fun NotificationDecisionSelectorsAreConsumedOncePerOriginalEntry() {
        val claims = NativeRequestActionClaims()
        assertTrue(claims.claim(NativeRequestAction.APPROVE)); assertFalse(claims.claim(NativeRequestAction.APPROVE))
        assertTrue(claims.claim(NativeRequestAction.DENY)); assertFalse(claims.claim(NativeRequestAction.DENY))
        repeat(2) { assertTrue(claims.claim(NativeRequestAction.DETAILS)) }
    }
    @Test fun LateOldNotificationCleanupCannotCancelOrRemoveReplacement() {
        val oldOwner = Any(); val newOwner = Any()
        val originalKey = "request:$key"
        val oldTag = NativeRequestRules.notificationTag(originalKey, locator)
        val newTag = NativeRequestRules.notificationTag(originalKey, "f".repeat(32))
        val notifications = linkedSetOf(oldTag)
        // Replacement withdraws the old tag even while a body reader holds it.
        notifications.remove(oldTag); notifications.add(newTag)
        // A delayed old publisher/reader cleanup can only cancel its own tag.
        notifications.remove(oldTag)
        assertEquals(setOf(newTag), notifications)
        assertFalse(NativeRequestRules.mayRemoveEntry(oldOwner, newOwner))
        assertFalse(NativeRequestRules.mayRemoveEntry(oldOwner, null))
        assertTrue(NativeRequestRules.mayRemoveEntry(newOwner, newOwner))
    }
}
