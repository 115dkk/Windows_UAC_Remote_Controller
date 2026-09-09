// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.background

import android.app.Activity
import android.app.Application
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import dev.dkk115.uacremote.ControllerApplication
import dev.dkk115.uacremote.nativecore.*
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean

internal sealed class NativeRequestReadReply {
    class Data(val value: NativeRequestPayload) : NativeRequestReadReply()
    class Failed(val status: NativeRequestActionResult) : NativeRequestReadReply()
    final override fun toString(): String = "NativeRequestReadReply([redacted])"
}

/** Scheduling/selection only; shares the existing actor worker and Rust owner. */
internal class NativeRequestCoordinator(
    private val application: Application,
    private val platform: AndroidNativePlatform,
    private val owner: () -> MobileController?,
    private val enqueue: (() -> Unit) -> Boolean,
    private val ready: () -> Boolean,
    private val approval: (NativeRequestSelection, Activity, (NativeApprovalReply) -> Unit) -> Boolean,
    private val denial: (NativeRequestSelection, (NativeDenialReply) -> Unit) -> NativeDenialReply,
    private val canApprove: (NativeRequestSelection) -> Boolean,
    private val canDeny: (NativeRequestSelection) -> Boolean,
    private val externalProgress: () -> Unit,
    private val ownerFailed: () -> Unit,
) {
    private val main = Handler(Looper.getMainLooper())
    private val stopped = AtomicBoolean(false)
    private val maintenanceQueued = AtomicBoolean(false)
    private val maintenanceWanted = AtomicBoolean(false)
    private val changeQueued = AtomicBoolean(false)
    private val detailsPending = AtomicBoolean(false)
    private val tickets = ConcurrentHashMap<ReadTicket, Unit>()
    private val requestAdmission = Any()
    private var actionCount = 0
    private var expiry: Runnable? = null
    private var lastFiredCutoff = 0uL
    private class ReadTicket(val callback: (NativeRequestReadReply) -> Unit, val details: Boolean) {
        @Volatile var value: NativeRequestReadReply? = null
        val done = AtomicBoolean(false)
    }

    fun progress() {
        maintenanceWanted.set(true)
        if (!stopped.get() && ready() && maintenanceQueued.compareAndSet(false, true)) {
            if (!enqueue {
                maintenanceWanted.set(false)
                try {
                    val controller = owner() ?: throw BridgeException.Closed()
                    platform.refreshPresentationClock()
                    val catalog = controller.maintainNativeRequests()
                    platform.requests.catalogMaintained(catalog)
                    advanceDeliveries(controller)
                    externalProgress()
                } catch (_: BridgeException.Busy) { }
                catch (_: BridgeException.PresentationRefreshRequired) { /* Real clock invalidation already queued rewarm. */ }
                catch (_: BridgeException.RequestUnavailable) { }
                catch (_: Exception) { ownerFailed() }
                finally {
                    maintenanceQueued.set(false); changed()
                    // Only another actual event received during this job asks
                    // for one additional pass; Busy itself never grants one.
                    if (maintenanceWanted.getAndSet(false)) progress()
                }
                // Do not self-poll a Busy result; only a new real event retries it.
            }) maintenanceQueued.set(false)
        }
    }
    /** A previously rejected queue insertion, not a retry of a Busy operation. */
    fun resumeQueued() { if (maintenanceWanted.get() && !maintenanceQueued.get()) progress() }

    /** Empty event is only a snapshot wake. It is never navigation/auth data. */
    fun changed() {
        if (!changeQueued.compareAndSet(false, true)) return
        if (!main.post {
            changeQueued.set(false)
            (application as? ControllerApplication)?.requestSnapshotChanged()
            expiry?.let { main.removeCallbacks(it) }; expiry = null
            if (!stopped.get() && ready()) {
                val until = platform.requests.nextWake()
                val now = SystemClock.elapsedRealtimeNanos()
                if (until != null && until > lastFiredCutoff && now >= 0) {
                    val delay = if (until <= now.toULong()) 1L else ((until - now.toULong()) / 1_000_000uL).coerceAtMost(60_000uL).toLong().coerceAtLeast(1)
                    val wake = Runnable { lastFiredCutoff = until; progress() }
                    expiry = wake; main.postDelayed(wake, delay)
                }
            }
        }) changeQueued.set(false)
    }

    fun read(locator: String?, callback: (NativeRequestReadReply) -> Unit) {
        val detail = locator != null
        val ticket = ReadTicket(callback, detail)
        synchronized(requestAdmission) {
            if (stopped.get() || !ready()) { reply(callback, NativeRequestReadReply.Failed(NativeRequestActionResult.UNAVAILABLE)); return }
            if (tickets.size >= 8 || (detail && !detailsPending.compareAndSet(false, true))) {
                reply(callback, NativeRequestReadReply.Failed(NativeRequestActionResult.BUSY)); return
            }
            tickets[ticket] = Unit
        }
        if (!enqueue {
            var claim: NativeRequestClaim? = null
            try {
                if (stopped.get() || !ready()) throw BridgeException.Closed()
                val controller = owner() ?: throw BridgeException.Closed()
                platform.refreshPresentationClock()
                val value = if (locator == null) {
                    val catalog = controller.requestCatalogStatus()
                    platform.requests.catalogMaintained(catalog)
                    val secure = platform.secureLockConfigured()
                    platform.requests.snapshot(catalog, { secure && canApprove(it) }, { secure && canDeny(it) })
                } else {
                    claim = platform.requests.acquire(locator) ?: throw BridgeException.RequestUnavailable()
                    val held = claim ?: throw BridgeException.RequestUnavailable()
                    controller.checkPendingRequest(held.handle)
                    platform.requests.details(held)
                }
                finishRead(ticket, NativeRequestReadReply.Data(value))
            } catch (_: BridgeException.Busy) { finishRead(ticket, NativeRequestReadReply.Failed(NativeRequestActionResult.BUSY)) }
            catch (_: BridgeException.RequestUnavailable) { finishRead(ticket, NativeRequestReadReply.Failed(NativeRequestActionResult.STALE)) }
            catch (_: Exception) { finishRead(ticket, NativeRequestReadReply.Failed(NativeRequestActionResult.UNAVAILABLE)) }
            finally { claim?.close() }
        }) finishRead(ticket, NativeRequestReadReply.Failed(NativeRequestActionResult.BUSY))
    }

    fun action(locator: String, action: NativeRequestAction, host: Activity?, route: NativeNotificationRoute?, callback: (NativeRequestActionResult) -> Unit) {
        synchronized(requestAdmission) {
            if (stopped.get() || !ready()) { actionReply(callback, NativeRequestActionResult.UNAVAILABLE); return }
            if (actionCount >= 8) { actionReply(callback, NativeRequestActionResult.BUSY); return }
            actionCount += 1
        }
        val claim = if (route == null) platform.requests.acquire(locator) else platform.requests.acquireNotification(route)
        if (claim == null) { releaseAction(); actionReply(callback, NativeRequestActionResult.STALE); return }
        if (!enqueue {
            var mainOwns = false
            try {
                if (stopped.get() || !ready()) throw BridgeException.Closed()
                val controller = owner() ?: throw BridgeException.Closed()
                val selected = controller.checkPendingRequest(claim.handle)
                if (!NativeRequestIdentity.same(selected, claim.selection) || !platform.requests.current(claim)) throw BridgeException.RequestUnavailable()
                if (action == NativeRequestAction.APPROVE && (!canApprove(selected) || claim.entry.phase != NativeRequestPhase.PENDING)) throw BridgeException.Busy()
                if (action == NativeRequestAction.DENY) {
                    val admitted = denial(selected) { result ->
                        val phase = when (result) {
                            NativeDenialReply.PREPARED, NativeDenialReply.WAITING, NativeDenialReply.BUSY -> NativeRequestPhase.WAITING
                            NativeDenialReply.SENDING -> NativeRequestPhase.SENDING
                            NativeDenialReply.AWAITING_OUTCOME -> NativeRequestPhase.AWAITING_OUTCOME
                            NativeDenialReply.CANCELLED, NativeDenialReply.RELEASED -> NativeRequestPhase.PENDING
                            NativeDenialReply.UNAVAILABLE -> NativeRequestPhase.UNAVAILABLE
                        }
                        platform.requests.phase(locator, phase); changed()
                    }
                    actionReply(callback, if (admitted == NativeDenialReply.WAITING) NativeRequestActionResult.QUEUED else if (admitted == NativeDenialReply.BUSY) NativeRequestActionResult.BUSY else NativeRequestActionResult.UNAVAILABLE, claim.entry)
                } else {
                    mainOwns = main.post {
                        try {
                            val app = application as? ControllerApplication
                            if (host == null || app?.isCurrentForegroundControllerHost(host) != true || stopped.get() || !ready() || !platform.requests.current(claim)) {
                                actionReply(callback, NativeRequestActionResult.STALE)
                            } else if (action == NativeRequestAction.DETAILS) {
                                platform.requests.openReview(claim); changed(); actionReply(callback, NativeRequestActionResult.QUEUED, claim.entry)
                            } else if (!canApprove(selected) || claim.entry.phase != NativeRequestPhase.PENDING) {
                                actionReply(callback, NativeRequestActionResult.BUSY)
                            } else {
                                platform.requests.openReview(claim)
                                platform.requests.phase(locator, NativeRequestPhase.AUTHENTICATING); changed()
                                val admitted = approval(selected, host) { result -> approvalResult(locator, result) }
                                actionReply(callback, if (admitted) NativeRequestActionResult.QUEUED else NativeRequestActionResult.BUSY, claim.entry)
                            }
                        } catch (_: Exception) { actionReply(callback, NativeRequestActionResult.UNAVAILABLE) }
                        finally { claim.close(); releaseAction() }
                    }
                    if (!mainOwns) actionReply(callback, NativeRequestActionResult.UNAVAILABLE)
                }
            } catch (_: BridgeException.Busy) { actionReply(callback, NativeRequestActionResult.BUSY) }
            catch (_: BridgeException.RequestUnavailable) { actionReply(callback, NativeRequestActionResult.STALE) }
            catch (_: Exception) { actionReply(callback, NativeRequestActionResult.UNAVAILABLE) }
            finally { if (!mainOwns) { claim.close(); releaseAction() } }
        }) { claim.close(); releaseAction(); actionReply(callback, NativeRequestActionResult.BUSY) }
    }

    private fun approvalResult(locator: String, result: NativeApprovalReply) {
        when (result) {
            is NativeApprovalReply.Prepared -> {
                if (!platform.requests.keepDelivery(locator, result.submission)) return
                platform.requests.phase(locator, NativeRequestPhase.WAITING)
                progress() // Actual retained submission is driven on the same worker.
            }
            NativeApprovalReply.Cancelled, NativeApprovalReply.Busy -> platform.requests.phase(locator, NativeRequestPhase.PENDING)
            NativeApprovalReply.Unavailable, NativeApprovalReply.LockRequired -> platform.requests.phase(locator, NativeRequestPhase.UNAVAILABLE)
        }
        changed()
    }
    private fun advanceDeliveries(controller: MobileController) {
        for ((locator, submission) in platform.requests.deliveries()) {
            val claim = platform.requests.acquire(locator) ?: continue
            try {
                controller.checkPendingRequest(claim.handle)
                if (!platform.requests.current(claim) || synchronized(claim.entry.lock) { claim.entry.delivery !== submission }) continue
                val current = submission.deliveryProgress()
                val progress = if (current == NativeDecisionProgress.PREPARED || current == NativeDecisionProgress.WAITING_FOR_PEER) {
                    controller.requestApprovalDelivery(submission)
                } else current
                platform.requests.phase(locator, when (progress) {
                    NativeDecisionProgress.PREPARED, NativeDecisionProgress.WAITING_FOR_PEER -> NativeRequestPhase.WAITING
                    NativeDecisionProgress.QUEUED -> NativeRequestPhase.SENDING
                    NativeDecisionProgress.WRITTEN_TO_SOCKET -> NativeRequestPhase.AWAITING_OUTCOME
                    NativeDecisionProgress.STOPPED, NativeDecisionProgress.REJECTED -> NativeRequestPhase.UNAVAILABLE
                })
            } catch (_: BridgeException.Busy) { }
            catch (_: Exception) { platform.requests.phase(locator, NativeRequestPhase.UNAVAILABLE) }
            finally { claim.close() }
        }
    }

    fun review(): NativeRequestReview = if (stopped.get() || !ready()) throw BridgeException.NativeUnavailable() else platform.requests.review()
    fun validReply(value: NativeRequestPayload): Boolean = !stopped.get() && ready() && platform.requests.validReply(value)
    fun stop() {
        if (!stopped.compareAndSet(false, true)) return
        main.post { expiry?.let { main.removeCallbacks(it) }; expiry = null }
        for (ticket in tickets.keys) finishRead(ticket, NativeRequestReadReply.Failed(NativeRequestActionResult.UNAVAILABLE))
        platform.stopRequests()
    }
    private fun finishRead(ticket: ReadTicket, result: NativeRequestReadReply) {
        ticket.value = if (stopped.get()) NativeRequestReadReply.Failed(NativeRequestActionResult.UNAVAILABLE) else result
        if (!main.post {
            if (ticket.done.compareAndSet(false, true)) {
                val value = ticket.value; ticket.value = null; tickets.remove(ticket)
                if (ticket.details) detailsPending.set(false)
                val safe = if (value is NativeRequestReadReply.Data && !validReply(value.value)) NativeRequestReadReply.Failed(NativeRequestActionResult.STALE)
                    else value ?: NativeRequestReadReply.Failed(NativeRequestActionResult.UNAVAILABLE)
                try { ticket.callback(safe) } catch (_: Exception) { }
            }
        }) { ticket.value = null; tickets.remove(ticket); ticket.done.set(true); if (ticket.details) detailsPending.set(false) }
    }
    private fun reply(callback: (NativeRequestReadReply) -> Unit, value: NativeRequestReadReply) {
        if (Looper.myLooper() == Looper.getMainLooper()) callback(value) else main.post { callback(value) }
    }
    private fun actionReply(callback: (NativeRequestActionResult) -> Unit, value: NativeRequestActionResult, original: NativeRequestEntry? = null) {
        val task = Runnable {
            val actual = if (value != NativeRequestActionResult.QUEUED) value
                else if (stopped.get() || !ready()) NativeRequestActionResult.UNAVAILABLE
                else {
                    val claim = original?.let { platform.requests.acquire(it.locator) }
                    val live = try { claim != null && claim.entry === original && platform.requests.current(claim) }
                        finally { claim?.close() }
                    if (live) value else NativeRequestActionResult.STALE
                }
            try { callback(actual) } catch (_: Exception) { }
        }
        if (Looper.myLooper() == Looper.getMainLooper()) task.run() else main.post(task)
    }
    private fun releaseAction() = synchronized(requestAdmission) { check(actionCount > 0); actionCount -= 1 }
    override fun toString(): String = "NativeRequestCoordinator(single_actor_worker)"
}
