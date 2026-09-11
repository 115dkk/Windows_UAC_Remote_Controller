// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.background

import android.app.Application
import android.app.Activity
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import dev.dkk115.uacremote.nativecore.BridgeException
import dev.dkk115.uacremote.nativecore.MobileController
import dev.dkk115.uacremote.nativecore.bridgeVersion
import dev.dkk115.uacremote.nativecore.uniffiEnsureInitialized
import dev.dkk115.uacremote.nativecore.NativeRequestSelection
import dev.dkk115.uacremote.nativecore.NativePairingScan
import dev.dkk115.uacremote.nativecore.NativePairingScanResult
import dev.dkk115.uacremote.pairing.PairingScanTicket
import dev.dkk115.uacremote.pairing.PairingScanStart
import dev.dkk115.uacremote.pairing.PairingScanRead
import dev.dkk115.uacremote.pairing.PairingScanRules
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

/**
 * One Application-lifetime worker and one real generated controller. No Activity,
 * generic work submission, untrusted request ingress or signing API.
 * UI callbacks run on main. Owner/storage work uses this sole worker; main
 * projection reads use only callback-free Rust getters and the light clock.
 */
internal class ApplicationPolicyActor(private val application: Application) {
    private enum class Operation { READ_POLICY, SAVE_POLICY, READ_HISTORY, CLEAR_HISTORY }
    private val lifecycle = PolicyOwnerLifecycle()
    private val bootTrace = OwnerBootTrace(BootDiagnostics::recordOwner)
    private val main = Handler(Looper.getMainLooper())
    private val pending = ConcurrentHashMap<PendingCall, Unit>()
    private val worker = ThreadPoolExecutor(
        1, 1, 0L, TimeUnit.MILLISECONDS, ArrayBlockingQueue<Runnable>(PolicyOwnerBounds.MAX_PENDING + 4),
        { action -> Thread(action, "uac-native-policy-owner").apply { isDaemon = true } },
        ThreadPoolExecutor.AbortPolicy(),
    )
    // Worker-thread-only. Never expose/clone this generated handle.
    private var controller: MobileController? = null
    private class PairingJob(val ticket: PairingScanTicket, val released: () -> Unit) {
        val scan = AtomicReference<NativePairingScan?>(null)
        val pending = AtomicBoolean(true)
        val accepted = AtomicBoolean(false)
        val cleanup = DenialCloseCursor(1)
    }
    private val pairingJob = AtomicReference<PairingJob?>(null)
    // Retain even if the Rust constructor fails after partially reopening keys.
    // This adapter owns only its own in-process references, never aliases.
    private val platform = AndroidNativePlatform(application)
    private val denials = DenialJobs(platform, { controller }, ::enqueueDenial,
        { lifecycle.phase() == PolicyOwnerPhase.READY }, { failOwner(PolicyStatus.STORAGE_UNAVAILABLE, OwnerFailureOrigin.DENIAL_OWNER) }, ::nativeCleanupProgress)
    private val approvals = ApplicationApprovalCoordinator(application, platform, { controller }, ::enqueueApproval,
        { failOwner(PolicyStatus.STORAGE_UNAVAILABLE, OwnerFailureOrigin.APPROVAL_OWNER) }, denials::blocksApproval, denials::nativeProgress)
    private val requests = NativeRequestCoordinator(application, platform, { controller }, ::enqueueRequest,
        { lifecycle.phase() == PolicyOwnerPhase.READY }, approvals::request, denials::request,
        approvals::canRequest, denials::canRequest, denials::externalProgress,
        { failOwner(PolicyStatus.UNAVAILABLE, OwnerFailureOrigin.REQUEST_MAINTENANCE) })
    private val keyReferenceCleanup = KeyReferenceCleanupState()
    private val cleanup = ControllerCleanupState()
    private val explicitCleanupRetry = AtomicBoolean(false)
    private val cleanupWake = AtomicBoolean(false)
    private val initializationTimeout = Runnable { failOwner(PolicyStatus.UNAVAILABLE, OwnerFailureOrigin.INIT_WATCHDOG) }
    @Volatile private var lifecycleObserver: ((PolicyOwnerPhase) -> Unit)? = null

    /** Read-only native service observation; CLOSED follows actual cleanup. */
    internal fun lifecyclePhase(): PolicyOwnerPhase = lifecycle.phase()
    internal fun observeLifecycle(observer: ((PolicyOwnerPhase) -> Unit)?) {
        lifecycleObserver = observer
        publishLifecycle()
    }
    private fun publishLifecycle() {
        val observer = lifecycleObserver ?: return
        val phase = lifecycle.phase()
        val action = Runnable {
            if (lifecycleObserver === observer) {
                try { observer(phase) } catch (_: Exception) { }
            }
        }
        if (Looper.myLooper() == Looper.getMainLooper()) action.run() else main.post(action)
    }

    init {
        platform.bindWithdrawal(approvals::withdraw, approvals::invalidateRequests)
        platform.bindDenials(denials)
        denials.bindCapture { job -> approvals.captureDenialDrain(job.selection) }
        platform.bindRequests(::nativeIntakeProgress, requests::changed, requests::progress, ::nativeCleanupProgress)
    }

    /** Native selection only; public locators first pass the original-handle check. */
    internal fun requestApproval(selection: NativeRequestSelection, host: Activity, callback: (NativeApprovalReply) -> Unit) =
        approvals.request(selection, host, callback)
    internal fun leaveApprovalRequest(host: Activity) = approvals.leaveRequest(host)
    /** Trusted native selection only; no arbitrary signing bytes are accepted. */
    internal fun requestDenial(selection: NativeRequestSelection, callback: (NativeDenialReply) -> Unit) = denials.request(selection, callback)
    internal fun readRequests(locator: String?, callback: (NativeRequestReadReply) -> Unit) = requests.read(locator, callback)
    internal fun requestAction(locator: String, action: NativeRequestAction, host: Activity?, route: NativeNotificationRoute?, callback: (NativeRequestActionResult) -> Unit) =
        requests.action(locator, action, host, route, callback)
    internal fun requestReview(): NativeRequestReview = requests.review()
    internal fun validRequestReply(value: NativeRequestPayload): Boolean = requests.validReply(value)
    internal fun maintainRequests() = requests.progress()
    internal fun invalidateRequestTime() { platform.invalidateRequestTime(); requests.progress() }

    internal fun hasPendingPairingScan(): Boolean = pairingJob.get() != null

    /** One fixed native scan operation on the existing worker, never a second owner. */
    internal fun beginPairingScan(ticket: PairingScanTicket, callback: (PairingScanStart) -> Unit, released: () -> Unit): Boolean {
        if (ticket.isCancelled() || lifecycle.phase() != PolicyOwnerPhase.READY) {
            pairingReply { callback(PairingScanStart.UNAVAILABLE) }; return false
        }
        if (lifecycle.admit() != null) { pairingReply { callback(PairingScanStart.BUSY) }; return false }
        val job = PairingJob(ticket, released)
        if (!pairingJob.compareAndSet(null, job)) {
            lifecycle.release(); pairingReply { callback(PairingScanStart.BUSY) }; return false
        }
        try {
            worker.execute {
                var result = PairingScanStart.UNAVAILABLE
                try {
                    if (!ticket.isCancelled() && lifecycle.phase() == PolicyOwnerPhase.READY) {
                        val owner = controller ?: throw BridgeException.Closed()
                        val scan = owner.beginPairingScan()
                        job.scan.set(scan)
                        if (ticket.isCancelled()) scan.cancel()
                        else { scan.checkCurrent(); result = PairingScanStart.READY }
                    }
                } catch (failure: Throwable) { rethrowFatal(failure) }
                finally {
                    if (result != PairingScanStart.READY) ticket.cancel()
                    job.pending.set(false); lifecycle.release()
                    cleanupPairingScan(false)
                    pairingReply { callback(if (ticket.isCancelled()) PairingScanStart.UNAVAILABLE else result) }
                    resumeQueuedWork(); cleanupIfStopped()
                }
            }
        } catch (_: RejectedExecutionException) {
            ticket.cancel(); job.pending.set(false); lifecycle.release()
            // No native operation was queued, so no generated handle can exist.
            pairingJob.compareAndSet(job, null)
            pairingReply { released(); callback(PairingScanStart.UNAVAILABLE) }
        }
        return true
    }

    /** Text comes only from the owned native decoder; no renderer/Intent ingress. */
    internal fun acceptPairingInvitation(ticket: PairingScanTicket, text: String, callback: (PairingScanRead) -> Unit) {
        val job = pairingJob.get()
        if (job == null || job.ticket !== ticket || ticket.isCancelled() || lifecycle.phase() != PolicyOwnerPhase.READY ||
            !job.accepted.compareAndSet(false, true)) {
            cancelPairingScan(ticket); pairingReply { callback(PairingScanRead.UNAVAILABLE) }; return
        }
        if (!PairingScanRules.boundedText(text)) {
            cancelPairingScan(ticket); pairingReply { callback(PairingScanRead.INVALID) }; return
        }
        if (!job.pending.compareAndSet(false, true)) {
            cancelPairingScan(ticket); pairingReply { callback(PairingScanRead.UNAVAILABLE) }; return
        }
        if (lifecycle.admit() != null) {
            job.pending.set(false); cancelPairingScan(ticket); pairingReply { callback(PairingScanRead.UNAVAILABLE) }; return
        }
        try {
            worker.execute {
                var result = PairingScanRead.UNAVAILABLE
                try {
                    if (!ticket.isCancelled() && lifecycle.phase() == PolicyOwnerPhase.READY) {
                        val scan = job.scan.get() ?: throw BridgeException.Closed()
                        scan.checkCurrent()
                        result = when (scan.acceptInvitation(text)) {
                            NativePairingScanResult.READ -> PairingScanRead.READ
                            NativePairingScanResult.INVALID -> PairingScanRead.INVALID
                            NativePairingScanResult.UNAVAILABLE -> PairingScanRead.UNAVAILABLE
                        }
                        if (result == PairingScanRead.READ) scan.checkCurrent()
                    }
                } catch (failure: Throwable) { rethrowFatal(failure); result = PairingScanRead.UNAVAILABLE }
                finally {
                    if (result != PairingScanRead.READ) ticket.cancel()
                    job.pending.set(false); lifecycle.release()
                    cleanupPairingScan(false)
                    pairingReply { callback(if (ticket.isCancelled() && result == PairingScanRead.READ) PairingScanRead.UNAVAILABLE else result) }
                    resumeQueuedWork(); cleanupIfStopped()
                }
            }
        } catch (_: RejectedExecutionException) {
            job.pending.set(false); lifecycle.release(); cancelPairingScan(ticket)
            pairingReply { callback(PairingScanRead.UNAVAILABLE) }
        }
    }

    /** Only cancel is allowed concurrently with the worker; Rust implements it atomically. */
    internal fun cancelPairingScan(ticket: PairingScanTicket) {
        ticket.cancel()
        val job = pairingJob.get()?.takeIf { it.ticket === ticket } ?: return
        try { job.scan.get()?.cancel() } catch (_: Exception) { /* terminal, cleanup remains retained */ }
        requestWorkerCleanup()
    }

    private fun pairingReply(action: () -> Unit) {
        main.post { try { action() } catch (_: Exception) { /* never transfer a detached reply */ } }
    }

    /** Worker only. Failed generated close remains owned until existing explicit cleanup retry. */
    private fun cleanupPairingScan(explicitRetry: Boolean) {
        val job = pairingJob.get() ?: return
        if (!job.ticket.isCancelled() || job.pending.get()) return
        val scan = job.scan.getAndSet(null)
        if (scan != null) {
            try { scan.cancel() } catch (_: Exception) { }
            try { job.cleanup.closeOrRetain(scan) } catch (_: Exception) { }
        }
        if (explicitRetry) job.cleanup.retryOnce()
        if (job.cleanup.complete() && pairingJob.compareAndSet(job, null)) pairingReply(job.released)
    }

    private fun enqueueRequest(action: () -> Unit): Boolean = try {
        worker.execute { try { action() } finally { resumeQueuedWork(); cleanupIfStopped() } }
        true
    } catch (_: RejectedExecutionException) { false }

    private fun enqueueApproval(action: () -> Unit): Boolean = try {
        worker.execute { try { action() } finally { resumeQueuedWork(); cleanupIfStopped() } }
        true
    } catch (_: RejectedExecutionException) { false }

    private fun enqueueDenial(action: () -> Unit): Boolean = try {
        worker.execute { try { action() } finally { resumeQueuedWork(); cleanupIfStopped() } }
        true
    } catch (_: RejectedExecutionException) { false }
    private fun resumeQueuedWork() { denials.resumeQueued(); requests.resumeQueued() }

    /** Rust publishes finished=true only after its I/O resources are drained,
     * then sends this fixed wake. A stopped request coordinator cannot consume
     * it: the retained controller still needs cleanup-only continuation.
     * STOPPING precedes the worker's first native shutdown. A completion after
     * that shutdown's pending-I/O check therefore selects CLEANUP; a completion
     * before STOPPING is already visible to the first Rust cleanup check.
     * No native callback synchronously re-enters/waits for MobileController. */
    private fun nativeIntakeProgress() {
        when (lifecycle.nativeProgressTarget()) {
            PolicyNativeProgressTarget.NONE -> Unit
            PolicyNativeProgressTarget.REQUEST_MAINTENANCE -> requests.progress()
            PolicyNativeProgressTarget.CLEANUP -> nativeCleanupProgress()
        }
    }

    /** Actual native cleanup progress may resume owner shutdown, not failed scope steps. */
    private fun nativeCleanupProgress() {
        cleanupWake.set(true)
        requestWorkerCleanup()
    }

    fun start() {
        if (!lifecycle.start()) return
        val started = SystemClock.elapsedRealtime()
        bootTrace.initializing(OwnerInitializationStep.QUEUED)
        if (!main.postDelayed(initializationTimeout, PolicyOwnerBounds.RESPONSE_TIMEOUT_MILLIS)) {
            traceOwnerFailure(PolicyStatus.UNAVAILABLE, OwnerFailureOrigin.INIT_TIMER_POST)
            lifecycle.fail(PolicyStatus.UNAVAILABLE)
            worker.shutdown()
            publishLifecycle()
            return
        }
        try { worker.execute { initialize(started) } }
        catch (_: RejectedExecutionException) { failOwner(PolicyStatus.UNAVAILABLE, OwnerFailureOrigin.INIT_WORKER_SCHEDULE) }
        // Initialization is queued before observers may submit startup reads.
        publishLifecycle()
    }

    fun readPolicy(callback: (PolicyReply) -> Unit) = submit(Operation.READ_POLICY, null, callback)
    fun readHistory(callback: (PolicyReply) -> Unit) = submit(Operation.READ_HISTORY, null, callback)
    fun clearHistory(callback: (PolicyReply) -> Unit) = submit(Operation.CLEAR_HISTORY, null, callback)

    fun savePolicy(policyJson: String, callback: (PolicyReply) -> Unit) {
        if (!PolicyOwnerBounds.validPolicyString(policyJson)) {
            deliverImmediate(callback, PolicyReply.Failed(PolicyStatus.INVALID_POLICY))
            return
        }
        submit(Operation.SAVE_POLICY, policyJson, callback)
    }

    /** Explicit asynchronous termination request, never an Activity lifecycle hook. */
    fun shutdown(explicitRetry: Boolean = false) {
        pairingJob.get()?.let { cancelPairingScan(it.ticket) }
        requests.stop()
        denials.stop()
        approvals.stop()
        if (explicitRetry) approvals.retryCleanup()
        lifecycle.stop()
        publishLifecycle()
        if (explicitRetry) explicitCleanupRetry.set(true)
        main.removeCallbacks(initializationTimeout)
        finishAll(PolicyStatus.UNAVAILABLE)
        requestWorkerCleanup()
    }

    private fun initialize(started: Long) {
        try {
            if (lifecycle.phase() != PolicyOwnerPhase.STARTING) return
            if (PolicyOwnerBounds.responseExpired(started, SystemClock.elapsedRealtime())) {
                failOwner(PolicyStatus.UNAVAILABLE, OwnerFailureOrigin.INIT_PRECHECK)
                return
            }
            bootTrace.initializing(OwnerInitializationStep.PACKAGED_LIBRARY)
            PackagedControllerLibrary.prepare(application)
            // Run the generator's contract/API checksum checks before any
            // controller operation; our coarse ABI number is not a substitute.
            bootTrace.initializing(OwnerInitializationStep.GENERATED_CONTRACT)
            uniffiEnsureInitialized()
            bootTrace.initializing(OwnerInitializationStep.BRIDGE_ABI)
            check(bridgeVersion() == ControllerLibraryPolicy.ABI_VERSION)
            // Rust alone decides initial creation versus adoption/migration.
            // In particular Kotlin never pre-clears notifications or retries a
            // failed open by creating a new store.
            bootTrace.initializing(OwnerInitializationStep.OPEN_NATIVE_OWNER)
            controller = MobileController.openOrInitialize(platform)
            if (!lifecycle.initialized(started, SystemClock.elapsedRealtime())) {
                failOwner(lifecycle.failure(), OwnerFailureOrigin.INIT_COMPLETION)
                return
            }
            bootTrace.ready()
            requests.progress()
        } catch (failure: Throwable) {
            rethrowFatal(failure)
            failOwner(failureStatus(failure, initializing = true), OwnerFailureOrigin.INIT_EXCEPTION, failure)
        } finally {
            main.removeCallbacks(initializationTimeout)
            publishLifecycle()
            cleanupIfStopped()
        }
    }

    private fun submit(operation: Operation, policyJson: String?, callback: (PolicyReply) -> Unit) {
        val rejected = lifecycle.admit()
        if (rejected != null) {
            deliverImmediate(callback, PolicyReply.Failed(rejected))
            return
        }
        val call = PendingCall(SystemClock.elapsedRealtime(), callback)
        pending[call] = Unit
        if (!main.postDelayed(call.timeout, PolicyOwnerBounds.RESPONSE_TIMEOUT_MILLIS)) {
            abandon(call, OwnerFailureOrigin.CALL_TIMER_POST)
            failOwner(PolicyStatus.UNAVAILABLE, OwnerFailureOrigin.CALL_TIMER_POST)
            return
        }
        try { worker.execute { runCall(call, operation, policyJson) } }
        catch (_: RejectedExecutionException) {
            deliver(call, PolicyReply.Failed(if (lifecycle.phase() == PolicyOwnerPhase.READY) PolicyStatus.BUSY else lifecycle.failure()))
        }
    }

    private fun runCall(call: PendingCall, operation: Operation, policyJson: String?) {
        try {
            if (call.finished()) return
            if (PolicyOwnerBounds.responseExpired(call.started, SystemClock.elapsedRealtime())) {
                failOwner(PolicyStatus.UNAVAILABLE, OwnerFailureOrigin.CALL_WORKER_DEADLINE)
                return
            }
            if (lifecycle.phase() != PolicyOwnerPhase.READY) {
                deliver(call, PolicyReply.Failed(lifecycle.failure()))
                return
            }
            val owner = controller ?: throw IllegalStateException("Native policy owner unavailable")
            val committed = when (operation) {
                Operation.READ_POLICY -> owner.notificationPolicyJson()
                Operation.SAVE_POLICY -> owner.saveNotificationPolicy(checkNotNull(policyJson))
                Operation.READ_HISTORY -> owner.historyJson()
                Operation.CLEAR_HISTORY -> owner.clearHistoryJson()
            }
            val history = operation == Operation.READ_HISTORY || operation == Operation.CLEAR_HISTORY
            val valid = if (history) PolicyOwnerBounds.validHistoryString(committed)
                else PolicyOwnerBounds.validPolicyString(committed)
            if (!valid) throw IllegalStateException("Native bounded result unavailable")
            // Result kind is fixed by this native method, not renderer data.
            deliver(call, if (history) PolicyReply.HistoryCommitted(committed) else PolicyReply.Committed(committed))
        } catch (failure: Throwable) {
            rethrowFatal(failure)
            val status = failureStatus(failure)
            if (status != PolicyStatus.INVALID_POLICY && status != PolicyStatus.BUSY && status != PolicyStatus.HISTORY_UNAVAILABLE) failOwner(status, OwnerFailureOrigin.CALL_EXCEPTION, failure)
            deliver(call, PolicyReply.Failed(status))
        } finally {
            denials.externalProgress()
            if (operation == Operation.SAVE_POLICY) requests.progress()
            resumeQueuedWork()
            cleanupIfStopped()
        }
    }

    private fun traceOwnerFailure(status: PolicyStatus, origin: OwnerFailureOrigin, failure: Throwable? = null) {
        try { bootTrace.failed(origin, BootDiagnostics.ownerFailureCategory(failure), status, lifecycle.phase()) }
        catch (_: Throwable) { /* Observations cannot replace the actual failure/cleanup. */ }
    }

    private fun failOwner(status: PolicyStatus, origin: OwnerFailureOrigin, failure: Throwable? = null) {
        traceOwnerFailure(status, origin, failure)
        pairingJob.get()?.let { cancelPairingScan(it.ticket) }
        requests.stop()
        denials.stop()
        approvals.stop()
        lifecycle.fail(status)
        publishLifecycle()
        main.removeCallbacks(initializationTimeout)
        finishAll(status)
        requestWorkerCleanup()
    }

    private fun finishAll(status: PolicyStatus) {
        // Admission counts active plus queued calls, so this walk is at most 8.
        for (call in pending.keys) deliver(call, PolicyReply.Failed(status))
    }

    private fun deliver(call: PendingCall, reply: PolicyReply) {
        val action = Runnable {
            val callback = call.takeCallback() ?: return@Runnable
            main.removeCallbacks(call.timeout)
            pending.remove(call)
            lifecycle.release()
            val expired = PolicyOwnerBounds.responseExpired(call.started, SystemClock.elapsedRealtime())
            if (expired) failOwner(PolicyStatus.UNAVAILABLE, OwnerFailureOrigin.CALL_MAIN_DEADLINE)
            val actual = if (expired || (reply !is PolicyReply.Failed && lifecycle.phase() != PolicyOwnerPhase.READY)) {
                PolicyReply.Failed(lifecycle.failure())
            } else reply
            safelyCallback(callback, actual)
        }
        if (Looper.myLooper() == Looper.getMainLooper()) action.run()
        else if (!main.post(action)) abandon(call, OwnerFailureOrigin.CALL_MAIN_POST)
    }

    private fun deliverImmediate(callback: (PolicyReply) -> Unit, reply: PolicyReply) {
        if (Looper.myLooper() == Looper.getMainLooper()) safelyCallback(callback, reply)
        else main.post { safelyCallback(callback, reply) }
    }

    private fun abandon(call: PendingCall, origin: OwnerFailureOrigin) {
        if (call.takeCallback() != null) {
            main.removeCallbacks(call.timeout)
            pending.remove(call)
            lifecycle.release()
        }
        traceOwnerFailure(PolicyStatus.UNAVAILABLE, origin)
        lifecycle.fail(PolicyStatus.UNAVAILABLE)
        publishLifecycle()
    }

    private fun requestWorkerCleanup() {
        try { worker.execute { cleanupIfStopped() } }
        catch (_: RejectedExecutionException) {
            // A full bounded queue already has worker jobs whose finally blocks
            // perform this cleanup. A stopped executor has already been cleaned.
        }
    }

    private fun cleanupIfStopped() {
        platform.requests.continueCleanup()
        approvals.cleanupOnWorker()
        if (lifecycle.phase() == PolicyOwnerPhase.STARTING || lifecycle.phase() == PolicyOwnerPhase.READY) {
            cleanupPairingScan(false)
            return
        }
        val explicitRetry = explicitCleanupRetry.getAndSet(false)
        val resumed = cleanupWake.getAndSet(false)
        cleanupPairingScan(explicitRetry)
        if (pairingJob.get() != null) return
        if (explicitRetry) platform.requests.retryCleanup()
        denials.prepareShutdownCleanup(explicitRetry)
        if (explicitRetry) {
            platform.retryUnboundDenialCleanup()
            platform.retryCreationArgumentCleanup()
        }
        val owner = controller
        if (owner != null) {
            val action = cleanup.next(explicitRetry, resumed)
            if (action == ControllerCleanupAction.NONE) return
            if (action == ControllerCleanupAction.SHUTDOWN_THEN_DESTROY) {
                try {
                    if (explicitRetry) owner.shutdownNativeOwner() else owner.continueNativeCleanup()
                    cleanup.shutdownSucceeded()
                } catch (failure: Throwable) {
                    rethrowFatal(failure)
                    cleanup.failed()
                    // Rust may already be closed while retaining cleanupPending.
                    // Keep its handle and this worker for an explicit retry.
                    return
                }
            }
            // Logical Rust close keeps exact core owners available for native
            // retirement. Never destroy the ABI handle while its native session
            // or scope wrappers still need cleanup-only calls through it.
            if (approvals.hasPendingCleanup() || !denials.ownerShutdownSucceeded() || !platform.denialReferencesClear() || !platform.requests.cleanupComplete()) return
            try {
                owner.close()
                cleanup.destroyed()
                controller = null
                approvals.retryCleanup()
            } catch (failure: Throwable) {
                rethrowFatal(failure)
                cleanup.failed()
                return
            }
        }
        if (!keyReferenceCleanup.complete()) {
            if (!keyReferenceCleanup.shouldAttempt(explicitRetry)) return
            try {
                platform.releaseLocalKeyReferences()
                keyReferenceCleanup.succeeded()
            } catch (failure: Throwable) {
                rethrowFatal(failure)
                keyReferenceCleanup.failed()
                // Keep this worker/adapter for an explicit retry even if no
                // Rust handle was returned by the failed constructor.
                return
            }
        }
        // An OS cancellation request is not a terminal callback. Keep the
        // already bounded worker available to release the last opaque handles
        // once native signing/prompt cleanup actually becomes quiescent.
        if (approvals.hasPendingCleanup() || denials.hasPendingCleanup() || !platform.requests.cleanupComplete()) return
        platform.closeRequestClock()
        lifecycle.closed()
        bootTrace.closed()
        worker.shutdown()
        publishLifecycle()
    }

    private inner class PendingCall(val started: Long, callback: (PolicyReply) -> Unit) {
        private var callback: ((PolicyReply) -> Unit)? = callback
        val timeout = Runnable { if (!finished()) failOwner(PolicyStatus.UNAVAILABLE, OwnerFailureOrigin.CALL_TIMEOUT) }
        @Synchronized fun takeCallback(): ((PolicyReply) -> Unit)? = callback.also { callback = null }
        @Synchronized fun finished(): Boolean = callback == null
    }

    private fun safelyCallback(callback: (PolicyReply) -> Unit, reply: PolicyReply) {
        try { callback(reply) } catch (_: Exception) {
            // A detached UI callback is not a reason to undo committed policy or
            // report a fabricated failure/success to another Activity.
        }
    }

    private fun failureStatus(error: Throwable, initializing: Boolean = false): PolicyStatus = when (error) {
        is BridgeException.InvalidPolicy -> if (initializing) PolicyStatus.STORAGE_UNAVAILABLE else PolicyStatus.INVALID_POLICY
        is BridgeException.Busy -> if (initializing) PolicyStatus.UNAVAILABLE else PolicyStatus.BUSY
        is BridgeException.HistoryTimeUnavailable -> if (initializing) PolicyStatus.UNAVAILABLE else PolicyStatus.HISTORY_UNAVAILABLE
        is BridgeException.DenialRejected -> PolicyStatus.UNAVAILABLE
        is BridgeException.StorageUnavailable, is BridgeException.LifecycleIntegrationRequired,
        is BridgeException.OwnerFaulted, is BridgeException.LocalKeysReconciliationRequired,
        is BridgeException.LocalKeysUnavailable -> PolicyStatus.STORAGE_UNAVAILABLE
        else -> PolicyStatus.UNAVAILABLE
    }

    private fun rethrowFatal(error: Throwable) {
        if (error is VirtualMachineError || error is ThreadDeath) throw error
    }
    override fun toString(): String = "ApplicationPolicyActor(single_native_worker)"
}
