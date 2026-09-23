// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.background

/** Spacing for the one prompt connection maintenance after a PC session ends.
 * At most one run per interval: a trigger inside the interval is deferred to
 * its end, never dropped, and triggers while a run is scheduled join it. Only
 * caller-supplied monotonic milliseconds; no dialing, address or peer state. */
internal class PromptRedialGate(private val intervalMillis: Long) {
    private var lastRun: Long? = null
    private var scheduled = false

    /** Delay before the one scheduled run, or null when a run is already scheduled. */
    @Synchronized fun request(now: Long): Long? {
        if (scheduled) return null
        scheduled = true
        val elapsed = now - (lastRun ?: return 0L)
        return if (elapsed < 0 || elapsed >= intervalMillis) 0L else intervalMillis - elapsed
    }

    /** The scheduled run started at [now]. */
    @Synchronized fun ran(now: Long) { scheduled = false; lastRun = now }

    /** The scheduled run could not be posted; the next trigger may schedule again. */
    @Synchronized fun abandoned() { scheduled = false }
}
