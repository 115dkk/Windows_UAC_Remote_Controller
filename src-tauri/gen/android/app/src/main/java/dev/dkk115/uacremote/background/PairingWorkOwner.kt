// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.background

import dev.dkk115.uacremote.pairing.PairingScanRead
import dev.dkk115.uacremote.pairing.PairingScanStart
import dev.dkk115.uacremote.pairing.PairingScanTicket
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

internal interface PairingWorkPlatform<Scan, Ceremony, Status> {
    fun beginScan(): Scan
    fun checkCurrent(scan: Scan)
    fun acceptInvitation(scan: Scan, text: String): PairingScanRead
    fun canCreateKeys(): Boolean
    fun beginCeremony(scan: Scan): Ceremony
    fun cancelScan(scan: Scan)
    fun cancelCeremony(ceremony: Ceremony)
    fun isSettled(ceremony: Ceremony): Boolean
    fun status(ceremony: Ceremony): Status
    fun confirm(ceremony: Ceremony)
}

/**
 * One scan and its original continuation on the actor's sole worker. Admission
 * ends after reading; starting the accepted invitation never asks for admission
 * again. Only cancellation and the main-thread host check cross worker ownership.
 */
internal class PairingWorkOwner<Scan : AutoCloseable, Ceremony : AutoCloseable, Status>(
    private val platform: PairingWorkPlatform<Scan, Ceremony, Status>,
    val ticket: PairingScanTicket,
    private val ready: () -> Boolean,
    private val post: (() -> Unit) -> Boolean,
    private val enqueue: (() -> Unit) -> Boolean,
    private val defer: (Long, () -> Unit) -> Boolean,
    private val removeDeferred: () -> Unit,
    private val requestCleanup: () -> Unit,
    private val released: () -> Unit,
    private val unavailableStatus: () -> Status,
    private val maxPolls: Int,
    private val pollIntervalMillis: Long,
) {
    private val scan = AtomicReference<Scan?>(null)
    private val ceremony = AtomicReference<Ceremony?>(null)
    private val pending = AtomicBoolean(true)
    private val accepted = AtomicBoolean(false)
    private val startPending = AtomicBoolean(false)
    private val pollScheduled = AtomicBoolean(false)
    private val completed = AtomicBoolean(false)
    // Worker only. Cancellation does not renew the observation budget or settle I/O.
    private var startAttempted = false
    private var polls = 0
    private var settled = false
    private var callback: ((Status) -> Unit)? = null
    private val cleanup = DenialCloseCursor(2)

    fun complete(): Boolean = completed.get()

    fun openOnWorker(): PairingScanStart {
        var result = PairingScanStart.UNAVAILABLE
        try {
            if (!ticket.isCancelled() && ready()) {
                val value = platform.beginScan()
                scan.set(value)
                if (ticket.isCancelled()) platform.cancelScan(value)
                else {
                    platform.checkCurrent(value)
                    result = PairingScanStart.READY
                }
            }
        } catch (failure: Throwable) { rethrowFatal(failure) }
        finally {
            if (result != PairingScanStart.READY) ticket.cancel()
            pending.set(false)
        }
        return result
    }

    fun reserveInvitation(): Boolean = !complete() && !ticket.isCancelled() &&
        accepted.compareAndSet(false, true) && pending.compareAndSet(false, true)

    fun abandonPending() { pending.set(false); cancel() }

    /** Called for the already admitted read, never for a retry or a second scan. */
    fun readInvitationOnWorker(
        text: String,
        currentHost: () -> Boolean,
        onStatus: (Status) -> Unit,
        onRead: (PairingScanRead) -> Unit,
    ) {
        var result = PairingScanRead.UNAVAILABLE
        try {
            if (!ticket.isCancelled() && ready()) {
                val value = checkNotNull(scan.get())
                platform.checkCurrent(value)
                result = platform.acceptInvitation(value, text)
                if (result == PairingScanRead.READ) platform.checkCurrent(value)
            }
        } catch (failure: Throwable) { rethrowFatal(failure); result = PairingScanRead.UNAVAILABLE }
        finally {
            if (result != PairingScanRead.READ) ticket.cancel()
            callback = if (result == PairingScanRead.READ) onStatus else null
            pending.set(false)
        }
        val read = result
        if (!post {
                // Host/origin and the Dialog's original lifetime are main-owned.
                // Check them before permitting any key-creating continuation.
                val permitted = read == PairingScanRead.READ && !ticket.isCancelled() && try {
                    currentHost()
                } catch (_: Exception) { false }
                if (read == PairingScanRead.READ && !permitted) cancel()
                val actual = if (read == PairingScanRead.READ && !permitted) PairingScanRead.UNAVAILABLE else read
                try { onRead(actual) } catch (_: Exception) { cancel() }
                if (permitted && !ticket.isCancelled() && !complete()) {
                    startPending.set(true)
                    // Queue pressure cannot revoke an accepted invitation. Any
                    // occupied worker's final cleanup pass resumes this same work.
                    enqueue { continueOnWorker() }
                }
            }) cancel()
    }

    /** Also called by the actor after each worker job if the queue was full. */
    fun continueOnWorker() {
        if (pending.get() || complete() || !startPending.compareAndSet(true, false) || startAttempted) return
        startAttempted = true
        if (ticket.isCancelled()) return
        try {
            check(ready() && platform.canCreateKeys())
            val value = checkNotNull(scan.get())
            platform.checkCurrent(value)
            if (ticket.isCancelled()) return
            ceremony.set(platform.beginCeremony(value))
            if (ticket.isCancelled()) ceremony.get()?.let(platform::cancelCeremony)
            schedulePoll()
        } catch (failure: Throwable) {
            rethrowFatal(failure)
            reportUnavailable()
            cancel()
        }
    }

    fun confirmOnWorker() {
        if (!ticket.isCancelled() && ready() && !complete()) ceremony.get()?.let(platform::confirm)
    }

    /** Native cancellation alone may run concurrently; it never releases a handle. */
    fun cancel() {
        ticket.cancel()
        try { ceremony.get()?.let(platform::cancelCeremony) } catch (_: Exception) { }
        try { scan.get()?.let(platform::cancelScan) } catch (_: Exception) { }
        requestCleanup()
    }

    private fun schedulePoll() {
        if (complete() || settled || pollScheduled.get()) return
        if (polls >= maxPolls) {
            reportUnavailable()
            cancel()
            return
        }
        polls++
        pollScheduled.set(true)
        val posted = defer(pollIntervalMillis) {
            if (!enqueue {
                    pollScheduled.set(false)
                    pollOnWorker()
                }) {
                pollScheduled.set(false)
                cancel()
            }
        }
        if (!posted) {
            pollScheduled.set(false)
            reportUnavailable()
            cancel()
        }
    }

    private fun pollOnWorker() {
        try {
            if (complete()) return
            val value = ceremony.get() ?: return
            // Observe settlement before status so the final status cannot be lost.
            settled = platform.isSettled(value)
            if (!ticket.isCancelled()) {
                val status = platform.status(value)
                val target = callback
                if (target != null) post { if (!ticket.isCancelled()) target(status) }
            }
            if (settled) callback = null else schedulePoll()
        } catch (failure: Throwable) {
            rethrowFatal(failure)
            reportUnavailable()
            cancel()
        }
    }

    private fun reportUnavailable() {
        val target = callback
        callback = null
        if (!ticket.isCancelled() && target != null) post { target(unavailableStatus()) }
    }

    /**
     * Worker only. A cancelled ceremony holds both handles until actual settlement.
     * Exhaustion retains them for native progress/explicit cleanup, not a fresh
     * poll budget. Failed generated closes require the same explicit retry as before.
     */
    fun cleanupOnWorker(explicitRetry: Boolean) {
        if (complete() || pending.get() || (!ticket.isCancelled() && !settled)) return
        val heldCeremony = ceremony.get()
        if (heldCeremony != null) {
            if (ticket.isCancelled()) callback = null
            val ended = try { platform.isSettled(heldCeremony) } catch (_: Exception) { false }
            if (!ended) {
                if (polls < maxPolls) schedulePoll()
                return
            }
            settled = true
            ceremony.set(null)
            removeDeferred()
            pollScheduled.set(false)
            try { cleanup.closeOrRetain(heldCeremony) } catch (_: Exception) { }
        }
        val heldScan = scan.getAndSet(null)
        if (heldScan != null) {
            try { platform.cancelScan(heldScan) } catch (_: Exception) { }
            try { cleanup.closeOrRetain(heldScan) } catch (_: Exception) { }
        }
        if (explicitRetry) cleanup.retryOnce()
        if (cleanup.complete() && completed.compareAndSet(false, true)) {
            callback = null
            startPending.set(false)
            removeDeferred()
            released()
        }
    }

    private fun rethrowFatal(failure: Throwable) {
        if (failure is VirtualMachineError || failure is ThreadDeath) throw failure
    }
    override fun toString(): String = "PairingWorkOwner([redacted])"
}
