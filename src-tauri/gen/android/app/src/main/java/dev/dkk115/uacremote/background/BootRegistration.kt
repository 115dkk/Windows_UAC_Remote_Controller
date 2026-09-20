// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.background

import android.app.Activity
import android.app.Application
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.system.Os
import android.system.OsConstants
import java.lang.ref.WeakReference
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/** Application-owned DE-only worker, independent of the credential-protected
 * Rust actor. One initialization and one mutation slot; no public work queue.
 * Main never performs file I/O or waits for the worker. */
internal class BootRegistration(private val application: Application, private val currentHost: (Activity) -> Boolean) {
    private val main = Handler(Looper.getMainLooper())
    private val worker = ThreadPoolExecutor(1, 1, 0L, TimeUnit.MILLISECONDS, ArrayBlockingQueue<Runnable>(1),
        { action -> Thread(action, "uac-boot-registration").apply { isDaemon = true } }, ThreadPoolExecutor.AbortPolicy())
    private val fence = BootRegistrationFence()
    private val observers = ArrayList<(Boolean) -> Unit>()
    @Volatile private var initializing = true
    private var initializationStarted = false
    private var host: WeakReference<Activity>? = null
    private var io: BootRegistrationIo? = null // Worker only.
    @Volatile var state = BootActivationState.LOADING
        private set
    @Volatile var uncertain = false
        private set
    val pending: Boolean get() = initializing || fence.current != null

    private fun workerIo(): BootRegistrationIo = io ?: run {
        check(Looper.myLooper() != Looper.getMainLooper())
        val context = application.createDeviceProtectedStorageContext()
        check(context.isDeviceProtectedStorage)
        val store = BootActivationFile(context.noBackupFilesDir) { directory ->
            val descriptor = Os.open(directory.absolutePath, OsConstants.O_RDONLY or OsConstants.O_CLOEXEC or OsConstants.O_NOFOLLOW, 0)
            try {
                check(OsConstants.S_ISDIR(Os.fstat(descriptor).st_mode))
                Os.fsync(descriptor)
            } finally { Os.close(descriptor) }
        }
        BootRegistrationIo(store, { ControllerForegroundService.legacyComponentState(context) },
            { ControllerForegroundService.componentState(context) }).also { io = it }
    }

    fun initialize() {
        check(Looper.myLooper() == Looper.getMainLooper())
        if (initializationStarted) return
        initializationStarted = true
        val started = SystemClock.elapsedRealtime()
        val cancelled = AtomicBoolean(false)
        val timeout = Runnable {
            cancelled.set(true)
            state = BootActivationState.UNAVAILABLE
            uncertain = true
            finishObservers(false) // The actual worker remains owned/initializing.
        }
        if (!main.postDelayed(timeout, BootServicePolicy.SERVICE_COMMAND_TIMEOUT_MILLIS)) {
            timeout.run(); initializing = false; return
        }
        try {
            worker.execute {
                val result = try { workerIo().initialize { !cancelled.get() && !BootServicePolicy.serviceCommandExpired(started, SystemClock.elapsedRealtime()) } }
                    catch (_: Exception) { BootRegistrationResult(BootActivationState.UNAVAILABLE, BootRegistrationFailure.STORAGE) }
                if (!main.post {
                    main.removeCallbacks(timeout)
                    initializing = false
                    val fresh = !cancelled.get() && !BootServicePolicy.serviceCommandExpired(started, SystemClock.elapsedRealtime())
                    state = if (fresh) result.state else BootActivationState.UNAVAILABLE
                    uncertain = !fresh || result.failure != null
                    record(BootDiagnosticStage.ACTIVATION_OBSERVED)
                    finishObservers(!uncertain)
                }) { uncertain = true; state = BootActivationState.UNAVAILABLE }
            }
        } catch (_: Exception) {
            main.removeCallbacks(timeout)
            initializing = false
            state = BootActivationState.UNAVAILABLE
            uncertain = true
            finishObservers(false)
        }
    }

    /** At most eight bounded initialization continuations, never a reload or
     * automatic repair of an existing OFF/unknown record. */
    fun whenObserved(callback: (Boolean) -> Unit) {
        check(Looper.myLooper() == Looper.getMainLooper())
        if (uncertain || !initializing) { safely(callback, !uncertain); return }
        if (observers.size >= 8) { safely(callback, false); return }
        observers.add(callback)
    }

    fun hostRetired(activity: Activity) {
        check(Looper.myLooper() == Looper.getMainLooper())
        if (host?.get() === activity) cancelStart()
    }

    fun cancelStart() {
        check(Looper.myLooper() == Looper.getMainLooper())
        if (fence.current?.operation == BootRegistrationOperation.START) {
            fence.cancelStart()
            uncertain = true
        }
    }

    fun mutate(activity: Activity, operation: BootRegistrationOperation, started: Long, callback: (BootRegistrationResult) -> Unit) {
        check(Looper.myLooper() == Looper.getMainLooper())
        if (initializing || state !in setOf(BootActivationState.ON, BootActivationState.OFF, BootActivationState.LEGACY_MISSING) ||
            (operation == BootRegistrationOperation.START && uncertain) || !currentHost(activity) ||
            BootServicePolicy.serviceCommandExpired(started, SystemClock.elapsedRealtime())) {
            safely(callback, BootRegistrationResult(state, BootRegistrationFailure.CANCELLED)); return
        }
        val ticket = fence.reserve(operation, started)
        if (ticket == null) { safely(callback, BootRegistrationResult(state, BootRegistrationFailure.CANCELLED)); return }
        host = WeakReference(activity)
        val expected = state
        var replied = false // Main only; timeout may reply but cannot release the slot.
        fun finishReply(value: BootRegistrationResult) {
            if (!replied) { replied = true; safely(callback, value) }
        }
        val timeout = Runnable {
            ticket.cancel()
            uncertain = true
            finishReply(BootRegistrationResult(state, BootRegistrationFailure.CANCELLED))
        }
        val remaining = BootServicePolicy.SERVICE_COMMAND_TIMEOUT_MILLIS - (SystemClock.elapsedRealtime() - started)
        if (remaining <= 0 || !main.postDelayed(timeout, remaining)) {
            fence.complete(ticket); host = null; timeout.run(); return
        }
        record(BootDiagnosticStage.ACTIVATION_MUTATION_STARTED)
        try {
            worker.execute {
                val result = try { workerIo().mutate(expected, operation) { ticket.mayContinue(SystemClock.elapsedRealtime()) } }
                    catch (_: Exception) { BootRegistrationResult(BootActivationState.UNAVAILABLE, BootRegistrationFailure.STORAGE) }
                if (!main.post {
                    main.removeCallbacks(timeout)
                    if (!fence.complete(ticket)) return@post
                    val fresh = ticket.mayContinue(SystemClock.elapsedRealtime()) &&
                        (operation != BootRegistrationOperation.START || (host?.get() === activity && currentHost(activity)))
                    host = null
                    state = result.state // Actual commit/readback; never claim rollback.
                    uncertain = !fresh || result.failure != null
                    record(BootDiagnosticStage.ACTIVATION_MUTATION_FINISHED)
                    finishReply(if (fresh) result else result.copy(failure = result.failure ?: BootRegistrationFailure.CANCELLED))
                }) { uncertain = true } // Retain exact ticket on unconfirmed delivery.
            }
        } catch (_: Exception) {
            main.removeCallbacks(timeout)
            fence.complete(ticket) // Rejected enqueue: no worker operation entered.
            host = null
            uncertain = true
            finishReply(BootRegistrationResult(state, BootRegistrationFailure.CANCELLED))
        }
    }

    private fun record(stage: BootDiagnosticStage) = BootDiagnostics.record(BootDiagnosticRecord(stage,
        activation = state, activationPending = pending, activationUncertain = uncertain))

    private fun finishObservers(available: Boolean) {
        val ready = observers.toList()
        observers.clear()
        for (callback in ready) safely(callback, available)
    }

    private fun <T> safely(callback: (T) -> Unit, value: T) { try { callback(value) } catch (_: Exception) { } }
}
