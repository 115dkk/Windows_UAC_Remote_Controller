// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.background

import org.junit.Assert.*
import org.junit.Test

class LanDiscoveryPolicyTest {
    private fun wanted(promoted: Boolean = true, retiring: Boolean = false, destroyed: Boolean = false,
        maintenanceReady: Boolean = true, localNetwork: Boolean = true,
        associations: UInt? = 2u, connected: UInt? = 1u) =
        LanDiscoveryPolicy.wanted(promoted, retiring, destroyed, maintenanceReady, localNetwork, associations, connected)

    @Test fun disconnectedPeerOnWifiOrEthernetWantsDiscovery() {
        assertTrue(wanted())
        assertTrue(wanted(associations = 1u, connected = 0u))
    }

    @Test fun everyLifetimeAndNetworkConditionIsRequired() {
        assertFalse(wanted(promoted = false))
        assertFalse(wanted(retiring = true))
        assertFalse(wanted(destroyed = true))
        assertFalse(wanted(maintenanceReady = false))
        assertFalse(wanted(localNetwork = false)) // Cellular, VPN without LAN transport, or no default.
    }

    @Test fun unknownStatusNeverStartsDiscovery() {
        assertFalse(wanted(associations = null, connected = null))
        assertFalse(wanted(associations = null))
        assertFalse(wanted(connected = null))
    }

    @Test fun connectedCatchingUpStopsDiscoveryAndLossRestartsIt() {
        assertTrue(wanted(associations = 2u, connected = 1u))
        assertFalse(wanted(associations = 2u, connected = 2u))
        assertTrue(wanted(associations = 2u, connected = 1u))
        assertFalse(wanted(associations = 0u, connected = 0u))
        assertFalse(wanted(associations = 1u, connected = 2u))
    }

    @Test fun resolveOnlyTheExactProtocolInstanceShape() {
        assertTrue(LanDiscoveryPolicy.matches("uacremote-0123456789abcdefabcd"))
        assertFalse(LanDiscoveryPolicy.matches("otherhost-0123456789abcdefabcd"))
        assertFalse(LanDiscoveryPolicy.matches("uacremote-0123456789abcdefabc"))
        assertFalse(LanDiscoveryPolicy.matches("uacremote-0123456789abcdefabcde"))
        assertFalse(LanDiscoveryPolicy.matches("uacremote-0123456789ABCDEFabcd"))
        assertFalse(LanDiscoveryPolicy.matches("uacremote-0123456789abcdefabcg"))
        assertFalse(LanDiscoveryPolicy.matches("uacremote-0123456789abcdefabcd.local"))
    }

    @Test fun callbackWaitingForReleaseStillOccupiesTheRegistrationCap() {
        val accounting = LanRegistrationAccounting(2)
        val first = requireNotNull(accounting.acquire())
        assertTrue(accounting.acquire() != null)
        assertEquals(2, accounting.occupied())

        first.beginRelease()
        assertEquals(2, accounting.occupied())
        assertNull(accounting.acquire())

        first.released()
        assertEquals(1, accounting.occupied())
        assertTrue(accounting.acquire() != null)
    }

    @Test fun missingReleaseCallbackRetriesWithBoundedBackoffAndKeepsTheCapOccupied() {
        var now = 100L
        val accounting = LanRegistrationAccounting(
            limit = 1,
            nowMillis = { now },
            initialRetryMillis = 10L,
            maxRetryMillis = 40L,
        )
        val lease = requireNotNull(accounting.acquire())

        assertEquals(LanRegistrationAccounting.ReleaseDecision.ATTEMPT, lease.beginRelease())
        assertEquals(10L, lease.unregisterAttemptFinished())
        assertEquals(1, accounting.occupied())
        assertNull(accounting.acquire())

        now += 9L
        assertEquals(LanRegistrationAccounting.ReleaseDecision.WAIT, lease.retryRelease())
        assertEquals(1L, lease.delayUntilRetry())
        now += 1L
        assertEquals(LanRegistrationAccounting.ReleaseDecision.ATTEMPT, lease.retryRelease())
        assertEquals(20L, lease.unregisterAttemptFinished())

        now += 20L
        assertEquals(LanRegistrationAccounting.ReleaseDecision.ATTEMPT, lease.retryRelease())
        assertEquals(40L, lease.unregisterAttemptFinished())
        now += 40L
        assertEquals(LanRegistrationAccounting.ReleaseDecision.ATTEMPT, lease.retryRelease())
        assertEquals(40L, lease.unregisterAttemptFinished())
        assertEquals(1, accounting.occupied())
        assertNull(accounting.acquire())
    }

    @Test fun confirmationAtARetryReturnsExactlyOneSlotAndDuplicatesAreIdempotent() {
        var now = 0L
        val accounting = LanRegistrationAccounting(1, { now }, 10L, 20L)
        val lease = requireNotNull(accounting.acquire())
        assertEquals(LanRegistrationAccounting.ReleaseDecision.ATTEMPT, lease.beginRelease())
        assertEquals(10L, lease.unregisterAttemptFinished())

        now = 10L
        assertEquals(LanRegistrationAccounting.ReleaseDecision.ATTEMPT, lease.retryRelease())
        lease.registrationAbsent()
        lease.registrationAbsent()
        lease.released()

        assertEquals(0, accounting.occupied())
        val replacement = requireNotNull(accounting.acquire())
        assertEquals(1, accounting.occupied())
        lease.released()
        assertEquals(1, accounting.occupied())
        replacement.registrationAbsent()
        assertEquals(0, accounting.occupied())
    }

    @Test fun discoveryRestartRetainsPendingReleaseAndDoesNotDoubleRelease() {
        var now = 0L
        val accounting = LanRegistrationAccounting(1, { now }, 10L, 20L)
        val oldSession = requireNotNull(accounting.acquire())
        assertEquals(LanRegistrationAccounting.ReleaseDecision.ATTEMPT, oldSession.beginRelease())
        assertEquals(10L, oldSession.unregisterAttemptFinished())

        // A replacement discovery session shares this owner-wide accounting.
        assertNull(accounting.acquire())
        now = 10L
        assertEquals(LanRegistrationAccounting.ReleaseDecision.ATTEMPT, oldSession.retryRelease())
        oldSession.released()

        val newSession = requireNotNull(accounting.acquire())
        oldSession.registrationAbsent()
        oldSession.released()
        assertEquals(1, accounting.occupied())
        newSession.registrationAbsent()
        assertEquals(0, accounting.occupied())
    }
}
