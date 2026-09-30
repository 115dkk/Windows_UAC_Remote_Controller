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
}
