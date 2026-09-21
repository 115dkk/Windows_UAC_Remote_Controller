// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.background

import org.junit.Assert.*
import org.junit.Test

class DefaultNetworkPolicyTest {
    @Test fun initialDefaultPromptsMaintenanceWithoutRetiringHealthyTransport() {
        val policy = DefaultNetworkPolicy(11)
        assertEquals(DefaultNetworkPolicy.Update(true, false), policy.consume())
        assertNull(policy.consume())
        assertFalse(policy.available(11))
        assertNull(policy.consume())
    }

    @Test fun startupWithoutDefaultSuppressesDialsUntilAnAvailableCallback() {
        val policy = DefaultNetworkPolicy(null)
        assertEquals(DefaultNetworkPolicy.Update(false, true), policy.consume())
        assertNull(policy.consume())
        assertTrue(policy.available(22))
        assertEquals(DefaultNetworkPolicy.Update(true, true), policy.consume())
    }

    @Test fun wifiToMobileCoalescesAndLateWifiLossCannotRetireMobile() {
        val policy = DefaultNetworkPolicy(11)
        policy.consume()
        assertTrue(policy.lost(11))
        assertTrue(policy.available(22))
        assertFalse(policy.lost(11))
        assertEquals(DefaultNetworkPolicy.Update(true, true), policy.consume())
        assertFalse(policy.lost(11))
        assertNull(policy.consume())
    }

    @Test fun availableBeforeOldLostStillProducesOnlyOneRetirement() {
        val policy = DefaultNetworkPolicy(11)
        policy.consume()
        assertTrue(policy.available(22))
        assertFalse(policy.lost(11))
        assertEquals(DefaultNetworkPolicy.Update(true, true), policy.consume())
        repeat(100) { assertFalse(policy.available(22)); assertFalse(policy.lost(11)) }
        assertNull(policy.consume())
    }

    @Test fun actualDefaultLossIsNotAnAuthenticationResult() {
        val policy = DefaultNetworkPolicy(11)
        policy.consume()
        assertTrue(policy.lost(11))
        assertEquals(DefaultNetworkPolicy.Update(false, true), policy.consume())
        assertFalse(policy.lost(11))
        assertNull(policy.consume())
    }

    @Test fun lossAndReturnOfSameIdentityStillRetiresInvalidatedTransport() {
        val policy = DefaultNetworkPolicy(11)
        policy.consume()
        policy.lost(11)
        policy.available(11)
        assertEquals(DefaultNetworkPolicy.Update(true, true), policy.consume())
        assertNull(policy.consume())
    }

    @Test fun initialCapabilitiesAndCapabilityJitterKeepHealthyVpnTransport() {
        val policy = DefaultNetworkPolicy(11)
        assertFalse(policy.capabilities(11, 18)) // Synthetic VPN + Wi-Fi bit set.
        assertEquals(DefaultNetworkPolicy.Update(true, false), policy.consume())
        repeat(100) { assertFalse(policy.capabilities(11, 18)) }
        assertNull(policy.consume())
    }

    @Test fun stableVpnIdentityWithWifiToMobileTransportChangeRetiresOnce() {
        val policy = DefaultNetworkPolicy(11)
        policy.consume()
        assertFalse(policy.capabilities(11, 18))
        assertTrue(policy.capabilities(11, 17)) // VPN + mobile, same default.
        assertEquals(DefaultNetworkPolicy.Update(true, true), policy.consume())
        assertFalse(policy.capabilities(11, 17))
        assertNull(policy.consume())
    }

    @Test fun staleCapabilitiesCannotChangeNewDefaultBaseline() {
        val policy = DefaultNetworkPolicy(11)
        policy.capabilities(11, 18)
        policy.consume()
        policy.available(22)
        assertFalse(policy.capabilities(11, 17))
        assertFalse(policy.capabilities(22, 17))
        assertEquals(DefaultNetworkPolicy.Update(true, true), policy.consume())
        assertFalse(policy.capabilities(11, 18))
        assertFalse(policy.capabilities(22, 17))
        assertNull(policy.consume())
    }

    @Test fun defaultReplacementBeforeCapabilitiesDoesNotCauseSecondReset() {
        val policy = DefaultNetworkPolicy(11)
        policy.capabilities(11, 18)
        policy.consume()
        policy.available(22)
        assertEquals(DefaultNetworkPolicy.Update(true, true), policy.consume())
        assertFalse(policy.capabilities(22, 17))
        assertNull(policy.consume())
    }

    @Test fun coalescedUnderlyingTransportChangeAndReturnStillInvalidatesCarrier() {
        val policy = DefaultNetworkPolicy(11)
        policy.capabilities(11, 18)
        policy.consume()
        assertTrue(policy.capabilities(11, 17))
        assertTrue(policy.capabilities(11, 18))
        assertEquals(DefaultNetworkPolicy.Update(true, true), policy.consume())
        assertNull(policy.consume())
    }
}
