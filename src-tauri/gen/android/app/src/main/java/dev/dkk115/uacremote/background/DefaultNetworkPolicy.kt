// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.background

/** Main-thread default-network identity and public transport types only. No addresses, SSIDs, routing,
 * credentials, authentication decisions or persisted state. */
internal class DefaultNetworkPolicy(initial: Long?) {
    private var current = initial
    private var applied = initial
    private var initialPending = true
    private var appliedNetworkLost = false
    private var transports: Int? = null
    private var transportChanged = false

    internal data class Update(val available: Boolean, val retireTransport: Boolean)

    fun available(identity: Long): Boolean {
        if (current == identity) return false
        current = identity
        transports = null
        return true
    }

    fun lost(identity: Long): Boolean {
        // A delayed loss for the old default must not retire its replacement.
        if (current != identity) return false
        if (applied == identity) appliedNetworkLost = true
        current = null
        transports = null
        return true
    }

    /** The first capabilities callback establishes a baseline. Later transport
     * changes also observe VPN underlying Wi-Fi/mobile changes while its default
     * Network identity stays constant. No volatile capability attributes enter. */
    fun capabilities(identity: Long, transportTypes: Int): Boolean {
        if (identity != current || transports == transportTypes) return false
        val previous = transports
        transports = transportTypes
        if (previous == null) return false
        transportChanged = true
        return true
    }

    fun consume(): Update? {
        if (!initialPending && !appliedNetworkLost && !transportChanged && current == applied) return null
        val update = Update(current != null,
            appliedNetworkLost || transportChanged || current != applied || (initialPending && current == null))
        applied = current
        initialPending = false
        appliedNetworkLost = false
        transportChanged = false
        return update
    }
}
