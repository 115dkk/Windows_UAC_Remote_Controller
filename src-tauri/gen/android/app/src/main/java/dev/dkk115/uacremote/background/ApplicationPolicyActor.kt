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
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/**
 * One Application-lifetime worker and one real generated controller. No Activity,
 * generic work submission, request ingress, signing or notification posting API.
 * Callbacks run on main, but all JNA/filesystem work stays on the sole worker.
 */
internal class ApplicationPolicyActor(private val application: Application) {
    private enum class Operation { READ_POLICY, SAVE_POLICY, READ_HISTORY, CLEAR_HISTORY }
    private val lifecycle = PolicyOwnerLifecycle()
    private val main = Handler(Looper.getMainLooper())
    private val pending = ConcurrentHashMap<PendingCall, Unit>()
    private val worker = ThreadPoolExecutor(
        1, 1, 0L, TimeUnit.MILLISECONDS, ArrayBlockingQueue<Runnable>(PolicyOwnerBounds.MAX_PENDING + 4),
        { action -> Thread(action, "uac-native-policy-owner").apply { isDaemon = true } },
        ThreadPoolExecutor.AbortPolicy(),
    )
    // Worker-thread-only. Never expose/clone this generated handle.
    private var controller: MobileController? = null
    // Retain even if the Rust constructor fails after partially reopening keys.
    // This adapter owns only its own in-process references, never aliases.
    private val platform = AndroidNativePlatform(application)
    private val approvals = ApplicationApprovalCoordinator(application, platform, { controller }, ::enqueueApproval) {
        failOwner(PolicyStatus.STORAGE_UNAVAILABLE)
    }
    private val keyReferenceCleanup = KeyReferenceCleanupState()
    private val cleanup = ControllerCleanupState()
    private val explicitCleanupRetry = AtomicBoolean(false)
    private val initializationTimeout = Runnable { failOwner(PolicyStatus.UNAVAILABLE) }
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

    init { platform.bindWithdrawal(approvals::withdraw, approvals::invalidateRequests) }

    /** Native selection only; no Tauri/intent ingress is exposed in this slice. */
    internal fun requestApproval(selection: NativeRequestSelection, host: Activity, callback: (NativeApprovalReply) -> Unit) =
        approvals.request(selection, host, callback)
    internal fun leaveApprovalRequest(host: Activity) = approvals.leaveRequest(host)

    private fun enqueueApproval(action: () -> Unit): Boolean = try {
        worker.execute { try { action() } finally { cleanupIfStopped() } }
        true
    } catch (_: RejectedExecutionException) { false }

    fun start() {
        if (!lifecycle.start()) return
        val started = SystemClock.elapsedRealtime()
        if (!main.postDelayed(initializationTimeout, PolicyOwnerBounds.RESPONSE_TIMEOUT_MILLIS)) {
            lifecycle.fail(PolicyStatus.UNAVAILABLE)
            worker.shutdown()
            publishLifecycle()
            return
        }
        try { worker.execute { initialize(started) } }
        catch (_: RejectedExecutionException) { failOwner(PolicyStatus.UNAVAILABLE) }
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
    fun shutdown() {
        approvals.stop()
        approvals.retryCleanup()
        lifecycle.stop()
        publishLifecycle()
        explicitCleanupRetry.set(true)
        main.removeCallbacks(initializationTimeout)
        finishAll(PolicyStatus.UNAVAILABLE)
        requestWorkerCleanup()
    }

    private fun initialize(started: Long) {
        try {
            if (lifecycle.phase() != PolicyOwnerPhase.STARTING) return
            if (PolicyOwnerBounds.responseExpired(started, SystemClock.elapsedRealtime())) {
                failOwner(PolicyStatus.UNAVAILABLE)
                return
            }
            PackagedControllerLibrary.prepare(application)
            // Run the generator's contract/API checksum checks before any
            // controller operation; our coarse ABI number is not a substitute.
            uniffiEnsureInitialized()
            check(bridgeVersion() == ControllerLibraryPolicy.ABI_VERSION)
            // Rust alone decides initial creation versus adoption/migration.
            // In particular Kotlin never pre-clears notifications or retries a
            // failed open by creating a new store.
            controller = MobileController.openOrInitialize(platform)
            if (!lifecycle.initialized(started, SystemClock.elapsedRealtime())) {
                failOwner(lifecycle.failure())
                return
            }
        } catch (failure: Throwable) {
            rethrowFatal(failure)
            failOwner(failureStatus(failure, initializing = true))
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
            abandon(call)
            failOwner(PolicyStatus.UNAVAILABLE)
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
                failOwner(PolicyStatus.UNAVAILABLE)
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
            if (status != PolicyStatus.INVALID_POLICY && status != PolicyStatus.BUSY && status != PolicyStatus.HISTORY_UNAVAILABLE) failOwner(status)
            deliver(call, PolicyReply.Failed(status))
        } finally {
            cleanupIfStopped()
        }
    }

    private fun failOwner(status: PolicyStatus) {
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
            if (expired) failOwner(PolicyStatus.UNAVAILABLE)
            val actual = if (expired || (reply !is PolicyReply.Failed && lifecycle.phase() != PolicyOwnerPhase.READY)) {
                PolicyReply.Failed(lifecycle.failure())
            } else reply
            safelyCallback(callback, actual)
        }
        if (Looper.myLooper() == Looper.getMainLooper()) action.run()
        else if (!main.post(action)) abandon(call)
    }

    private fun deliverImmediate(callback: (PolicyReply) -> Unit, reply: PolicyReply) {
        if (Looper.myLooper() == Looper.getMainLooper()) safelyCallback(callback, reply)
        else main.post { safelyCallback(callback, reply) }
    }

    private fun abandon(call: PendingCall) {
        if (call.takeCallback() != null) {
            main.removeCallbacks(call.timeout)
            pending.remove(call)
            lifecycle.release()
        }
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
        approvals.cleanupOnWorker()
        if (lifecycle.phase() == PolicyOwnerPhase.STARTING || lifecycle.phase() == PolicyOwnerPhase.READY) return
        val explicitRetry = explicitCleanupRetry.getAndSet(false)
        val owner = controller
        if (owner != null) {
            val action = cleanup.next(explicitRetry)
            if (action == ControllerCleanupAction.NONE) return
            if (action == ControllerCleanupAction.SHUTDOWN_THEN_DESTROY) {
                try {
                    owner.shutdownNativeOwner()
                    cleanup.shutdownSucceeded()
                } catch (failure: Throwable) {
                    rethrowFatal(failure)
                    cleanup.failed()
                    // Rust may already be closed while retaining cleanupPending.
                    // Keep its handle and this worker for an explicit retry.
                    return
                }
            }
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
        if (approvals.hasPendingCleanup()) return
        lifecycle.closed()
        worker.shutdown()
        publishLifecycle()
    }

    private inner class PendingCall(val started: Long, callback: (PolicyReply) -> Unit) {
        private var callback: ((PolicyReply) -> Unit)? = callback
        val timeout = Runnable { if (!finished()) failOwner(PolicyStatus.UNAVAILABLE) }
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
