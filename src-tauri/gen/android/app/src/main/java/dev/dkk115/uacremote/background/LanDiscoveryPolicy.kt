// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.background

/** Routing-hint discovery only. A discovered address never establishes PC identity. */
internal object LanDiscoveryPolicy {
    fun wanted(promoted: Boolean, retiring: Boolean, destroyed: Boolean, maintenanceReady: Boolean,
        localNetwork: Boolean, associations: UInt?, connected: UInt?): Boolean =
        promoted && !retiring && !destroyed && maintenanceReady && localNetwork &&
            associations != null && connected != null && associations > connected

    fun matches(instance: String): Boolean = instance.length == 30 && instance.startsWith("uacremote-") &&
        instance.drop(10).all { it in '0'..'9' || it in 'a'..'f' }
}
