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
import java.util.concurrent.atomic.AtomicInteger

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
    private val ownerFailed: (Throwable) -> Unit,
    private val maintenanceFailed: (Throwable) -> Unit,
) {
    private val main = Handler(Looper.getMainLooper())
    private val stopped = AtomicBoolean(false)
    private val maintenanceQueued = AtomicBoolean(false)
    private val maintenanceWanted = AtomicBoolean(false)
    // Consecutive, so one finished pass clears the record. Small, because a
    // request the owner cannot maintain is one the user is waiting on.
    private val maintenanceFailures = AtomicInteger(0)
    private val changeQueued = AtomicBoolean(false)
    private val detailsPending = AtomicBoolean(false)
    private val tickets = ConcurrentHashMap<ReadTicket, Unit>()
    private val requestAdmission = Any()
    private var actionCount = 0
    private var presentationRefreshing = false // guarded by requestAdmission
    private val notificationRefreshes = NotificationRefreshQueue<NativeRequestClaim>()
    private val notificationRefreshQueued = AtomicBoolean(false)
    private var expiry: Runnable? = null
    private var lastFiredCutoff = 0uL
    private class ReadTicket(val callback: (NativeRequestReadReply) -> Unit, val details: Boolean) {
        @Volatile var value: NativeRequestReadReply? = null
        val done = AtomicBoolean(false)
    }

    fun progress() {
        notificationRefreshes.progress() // Actual native/time/lifecycle progress, not a Busy retry.
        scheduleNotificationRefresh()
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
                    maintenanceFailures.set(0)
                } catch (_: BridgeException.Busy) { }
                catch (_: BridgeException.PresentationRefreshRequired) { /* Real clock invalidation already queued rewarm. */ }
                catch (_: BridgeException.RequestUnavailable) { }
                catch (failure: Exception) { maintenanceFailure(failure) }
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
    fun resumeQueued() {
        if (maintenanceWanted.get() && !maintenanceQueued.get()) progress()
        scheduleNotificationRefresh() // Only queue-insertion failures remain eligible.
    }

    /**
     * What one failed maintenance pass costs. It used to cost the whole owner,
     * on the first unexpected exception, and the handler discarded the reason,
     * so the trace could only say NOT_CAPTURED. One pass is small enough to
     * fail on its own: the next real event runs another one.
     *
     * A bridge failure the owner cannot work through still retires it at once,
     * by the same rule the approval coordinator already uses. Anything else is
     * survived and counted, and an unbroken run of them retires it too, because
     * an owner that can never finish a pass is not serving anyone either.
     */
    private fun maintenanceFailure(failure: Exception) {
        val consecutive = maintenanceFailures.incrementAndGet()
        if (fatal(failure) || consecutive > PolicyOwnerBounds.MAX_CONSECUTIVE_MAINTENANCE_FAILURES) {
            ownerFailed(failure)
        }
        else maintenanceFailed(failure)
    }

    /** The approval coordinator's rule, applied to the same kind of boundary: a
     * bridge error the owner declared, minus the ones it can carry on through. */
    private fun fatal(failure: Throwable): Boolean = failure is BridgeException &&
        failure !is BridgeException.Busy && failure !is BridgeException.InvalidPolicy &&
        failure !is BridgeException.RequestUnavailable &&
        failure !is BridgeException.PresentationRefreshRequired

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
        val rejected = synchronized(requestAdmission) {
            if (stopped.get() || !ready()) NativeRequestActionResult.UNAVAILABLE
            else if (presentationRefreshing || actionCount >= 8) NativeRequestActionResult.BUSY
            else { actionCount += 1; null }
        }
        if (rejected != null) {
            if (rejected == NativeRequestActionResult.BUSY) retainNotificationRefresh(route)
            actionReply(callback, rejected); return
        }
        val claim = if (route == null) platform.requests.acquire(locator) else platform.requests.acquireNotification(route)
        if (claim == null) { releaseAction(); actionReply(callback, NativeRequestActionResult.STALE); return }
        if (!enqueue {
            var mainOwns = false
            var dispatched = false
            try {
                if (stopped.get() || !ready()) throw BridgeException.Closed()
                val controller = owner() ?: throw BridgeException.Closed()
                val selected = controller.checkPendingRequest(claim.handle)
                if (!NativeRequestIdentity.same(selected, claim.selection) || !platform.requests.current(claim)) throw BridgeException.RequestUnavailable()
                if (action == NativeRequestAction.APPROVE && (!canApprove(selected) || claim.entry.phase != NativeRequestPhase.PENDING)) throw BridgeException.Busy()
                if (action == NativeRequestAction.DENY) {
                    val observation = NativeDecisionObservation()
                    val generation = NativeActionGeneration()
                    dispatched = true
                    val admitted = synchronized(claim.entry.actionAdmissionLock) {
                        val result = denial(selected) { reply ->
                            if (reply == NativeDenialReply.PREPARED) platform.requests.decisionPrepared(locator, observation)
                            val phase = when (reply) {
                                NativeDenialReply.PREPARED, NativeDenialReply.WAITING, NativeDenialReply.BUSY -> NativeRequestPhase.WAITING
                                NativeDenialReply.SENDING -> NativeRequestPhase.SENDING
                                NativeDenialReply.AWAITING_OUTCOME -> NativeRequestPhase.AWAITING_OUTCOME
                                NativeDenialReply.CANCELLED, NativeDenialReply.RELEASED -> NativeRequestPhase.PENDING
                                NativeDenialReply.UNAVAILABLE -> NativeRequestPhase.UNAVAILABLE
                            }
                            platform.requests.phase(locator, generation, phase, observation); changed()
                        }
                        if (result == NativeDenialReply.WAITING) {
                            platform.requests.actionAdmitted(claim, generation, NativeRequestPhase.WAITING)
                            platform.requests.decisionAccepted(claim, action, observation)
                        }
                        result
                    }
                    actionReply(callback, if (admitted == NativeDenialReply.WAITING) NativeRequestActionResult.QUEUED else if (admitted == NativeDenialReply.BUSY) NativeRequestActionResult.BUSY else NativeRequestActionResult.UNAVAILABLE, claim.entry)
                } else {
                    dispatched = true
                    mainOwns = main.post {
                        try {
                            val app = application as? ControllerApplication
                            if (host == null || app?.isCurrentForegroundControllerHost(host) != true || stopped.get() || !ready() || !platform.requests.current(claim)) {
                                actionReply(callback, NativeRequestActionResult.STALE)
                            } else if (action == NativeRequestAction.DETAILS) {
                                platform.requests.openReview(claim); changed(); actionReply(callback, NativeRequestActionResult.QUEUED, claim.entry)
                            } else if (!canApprove(selected) || claim.entry.phase != NativeRequestPhase.PENDING) {
                                if (claim.entry.phase == NativeRequestPhase.PENDING) retainNotificationRefresh(route, claim)
                                actionReply(callback, NativeRequestActionResult.BUSY)
                            } else {
                                platform.requests.openReview(claim)
                                val observation = NativeDecisionObservation()
                                val generation = NativeActionGeneration()
                                val admitted = synchronized(claim.entry.actionAdmissionLock) {
                                    val accepted = approval(selected, host) { result -> approvalResult(locator, generation, observation, result) }
                                    if (accepted) {
                                        platform.requests.actionAdmitted(claim, generation, NativeRequestPhase.AUTHENTICATING)
                                        platform.requests.decisionAccepted(claim, action, observation)
                                    }
                                    accepted
                                }
                                actionReply(callback, if (admitted) NativeRequestActionResult.QUEUED else NativeRequestActionResult.BUSY, claim.entry)
                            }
                        } catch (_: Exception) { actionReply(callback, NativeRequestActionResult.UNAVAILABLE) }
                        finally { claim.close(); releaseAction() }
                    }
                    if (!mainOwns) actionReply(callback, NativeRequestActionResult.UNAVAILABLE)
                }
            } catch (_: BridgeException.Busy) {
                // Only a definite pre-dispatch rejection permits a new ticket.
                // Unknown or partial admission never grants a presentation retry.
                if (!dispatched) retainNotificationRefresh(route, claim)
                actionReply(callback, NativeRequestActionResult.BUSY)
            }
            catch (_: BridgeException.RequestUnavailable) { actionReply(callback, NativeRequestActionResult.STALE) }
            catch (_: BridgeException.PresentationRefreshRequired) {
                // A real clock/presentation invalidation asks for maintenance,
                // never replays the consumed notification or action itself.
                progress(); actionReply(callback, NativeRequestActionResult.STALE)
            }
            catch (_: Exception) { actionReply(callback, NativeRequestActionResult.UNAVAILABLE) }
            finally { if (!mainOwns) { claim.close(); releaseAction() } }
        }) {
            retainNotificationRefresh(route, claim)
            claim.close(); releaseAction(); actionReply(callback, NativeRequestActionResult.BUSY)
        }
    }

    /** A failed notification tap may spend its OS one-shot selector. Retain only
     * the SAME original handle for a fresh presentation, never repeat its action. */
    private fun retainNotificationRefresh(route: NativeNotificationRoute?, original: NativeRequestClaim? = null) {
        if (route == null || route.action == NativeRequestAction.DETAILS || stopped.get() || !ready()) return
        val held = if (original == null) platform.requests.acquireNotification(route)
            else platform.requests.acquire(original.locator)
        if (held == null) return
        if (held.entry.phase != NativeRequestPhase.PENDING ||
            (original != null && held.entry !== original.entry) ||
            !notificationRefreshes.offer(held.entry.key, held)) {
            held.close(); return
        }
        scheduleNotificationRefresh()
    }

    private fun scheduleNotificationRefresh() {
        if (stopped.get() || !ready() || !notificationRefreshes.eligible() ||
            !notificationRefreshQueued.compareAndSet(false, true)) return
        if (!enqueue {
            val ticket = notificationRefreshes.take()
            var busy = false
            var publicationReserved = false
            try {
                if (ticket != null && !stopped.get() && ready() && platform.requests.current(ticket.value) &&
                    ticket.value.entry.phase == NativeRequestPhase.PENDING) {
                    // A new presentation changes the locator. Never invalidate a
                    // queued original Activity callback, auth session or denial
                    // delivery: wait for their actual admission/cleanup to end.
                    publicationReserved = synchronized(requestAdmission) {
                        if (actionCount != 0 || presentationRefreshing) false
                        else { presentationRefreshing = true; true }
                    }
                    if (!publicationReserved || !canApprove(ticket.value.selection) || !canDeny(ticket.value.selection)) busy = true
                    else {
                        notificationRefreshes.attempted(ticket)
                        val controller = owner() ?: throw BridgeException.Closed()
                        controller.refreshNativeRequest(ticket.value.handle)
                    }
                }
            } catch (_: BridgeException.Busy) { busy = true }
            catch (_: BridgeException.RequestUnavailable) { }
            catch (_: BridgeException.PresentationRefreshRequired) { /* Existing real invalidation queues rewarm. */ }
            catch (failure: Exception) { maintenanceFailure(failure) }
            finally {
                if (publicationReserved) synchronized(requestAdmission) { presentationRefreshing = false }
                if (ticket != null) notificationRefreshes.finish(ticket, busy)?.close()
                notificationRefreshQueued.set(false)
                changed()
            }
            // No self-retry. Actor queue release may run another eligible ticket;
            // a native Busy ticket requires new progress and has a two-try cap.
        }) notificationRefreshQueued.set(false)
    }

    private fun approvalResult(locator: String, generation: NativeActionGeneration, observation: NativeDecisionObservation, result: NativeApprovalReply) {
        when (result) {
            is NativeApprovalReply.Prepared -> {
                platform.requests.decisionPrepared(locator, observation, result.authenticatedAtNanos, result.signedAtNanos)
                if (!platform.requests.keepDelivery(locator, generation, result.submission, observation)) {
                    platform.requests.decisionLocalStatus(locator, observation); changed(); return
                }
                platform.requests.phase(locator, generation, NativeRequestPhase.WAITING, observation)
                progress() // Actual retained submission is driven on the same worker.
            }
            NativeApprovalReply.Cancelled, NativeApprovalReply.Busy -> {
                platform.requests.decisionLocalStatus(locator, observation)
                platform.requests.phase(locator, generation, NativeRequestPhase.PENDING, observation)
            }
            NativeApprovalReply.AuthenticationCancelled -> {
                platform.requests.decisionLocalStatus(locator, observation, authenticationCancelled = true)
                platform.requests.phase(locator, generation, NativeRequestPhase.PENDING, observation)
            }
            NativeApprovalReply.Unavailable, NativeApprovalReply.LockRequired -> {
                platform.requests.decisionLocalStatus(locator, observation)
                platform.requests.phase(locator, generation, NativeRequestPhase.UNAVAILABLE, observation)
            }
        }
        changed()
    }
    private fun advanceDeliveries(controller: MobileController) {
        for (delivery in platform.requests.deliveries()) {
            val locator = delivery.locator
            val submission = delivery.submission
            val generation = delivery.generation
            val observation = delivery.observation
            val claim = platform.requests.acquire(locator) ?: continue
            try {
                controller.checkPendingRequest(claim.handle)
                if (!platform.requests.current(claim) || synchronized(claim.entry.lock) { claim.entry.delivery !== submission }) continue
                val current = submission.deliveryProgress()
                val progress = if (current == NativeDecisionProgress.PREPARED || current == NativeDecisionProgress.WAITING_FOR_PEER) {
                    controller.requestApprovalDelivery(submission)
                } else current
                platform.requests.phase(locator, generation, when (progress) {
                    NativeDecisionProgress.PREPARED, NativeDecisionProgress.WAITING_FOR_PEER -> NativeRequestPhase.WAITING
                    NativeDecisionProgress.QUEUED -> NativeRequestPhase.SENDING
                    NativeDecisionProgress.WRITTEN_TO_SOCKET -> NativeRequestPhase.AWAITING_OUTCOME
                    NativeDecisionProgress.STOPPED, NativeDecisionProgress.REJECTED -> NativeRequestPhase.UNAVAILABLE
                }, observation)
            } catch (_: BridgeException.Busy) { }
            catch (_: Exception) { platform.requests.phase(locator, generation, NativeRequestPhase.UNAVAILABLE, observation) }
            finally { claim.close() }
        }
    }

    fun review(): NativeRequestReview = if (stopped.get() || !ready()) throw BridgeException.NativeUnavailable() else platform.requests.review()
    fun validReply(value: NativeRequestPayload): Boolean = !stopped.get() && ready() && platform.requests.validReply(value)
    fun stop() {
        if (!stopped.compareAndSet(false, true)) return
        for (claim in notificationRefreshes.stop()) claim.close()
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
    private fun releaseAction() {
        synchronized(requestAdmission) { check(actionCount > 0); actionCount -= 1 }
        notificationRefreshes.progress() // Actual action callback ownership ended.
        scheduleNotificationRefresh()
    }
    override fun toString(): String = "NativeRequestCoordinator(single_actor_worker)"
}
