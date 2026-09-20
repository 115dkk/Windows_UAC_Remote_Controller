// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.background

/** Bounded ownership for presentation-only refreshes after definite no-admission.
 * Values are original borrowed handles, never commands or decision permits. */
internal class NotificationRefreshQueue<T : Any>(private val maximum: Int = 32) {
    init { require(maximum in 1..32) }
    internal class Ticket<T : Any>(val key: String, val value: T) {
        var running = false
        var waitingForProgress = false
        var attempts = 0
    }
    private val entries = LinkedHashMap<String, Ticket<T>>()
    private var stopped = false

    @Synchronized fun offer(key: String, value: T): Boolean {
        if (stopped || entries.size >= maximum || entries.containsKey(key)) return false
        entries[key] = Ticket(key, value)
        return true
    }
    @Synchronized fun eligible(): Boolean = !stopped && entries.values.any { !it.running && !it.waitingForProgress }
    @Synchronized fun take(): Ticket<T>? {
        if (stopped) return null
        val ticket = entries.values.firstOrNull { !it.running && !it.waitingForProgress } ?: return null
        ticket.running = true
        return ticket
    }
    @Synchronized fun attempted(ticket: Ticket<T>) {
        check(entries[ticket.key] === ticket && ticket.running && ticket.attempts < 2)
        ticket.attempts += 1
    }
    /** Returns the exact value whose ownership may be released now. Busy never
     * itself admits another attempt; at most one later real-progress attempt. */
    @Synchronized fun finish(ticket: Ticket<T>, busy: Boolean): T? {
        check(entries[ticket.key] === ticket && ticket.running)
        ticket.running = false
        if (!stopped && busy && ticket.attempts < 2) {
            ticket.waitingForProgress = true
            return null
        }
        entries.remove(ticket.key)
        return ticket.value
    }
    @Synchronized fun progress() {
        if (!stopped) entries.values.filter { !it.running }.forEach { it.waitingForProgress = false }
    }
    /** In-flight native calls retain their borrow until their actual completion. */
    @Synchronized fun stop(): List<T> {
        stopped = true
        val pending = entries.values.filter { !it.running }
        pending.forEach { entries.remove(it.key) }
        return pending.map { it.value }
    }
}
