// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.security

import dev.dkk115.uacremote.AppLanguage
import dev.dkk115.uacremote.R

import android.app.Activity
import android.content.Context
import android.hardware.biometrics.BiometricPrompt
import android.os.CancellationSignal
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import dev.dkk115.uacremote.nativecore.NativeApprovalAttempt
import dev.dkk115.uacremote.nativecore.NativeApprovalPlan
import java.security.Signature

/**
 * Native-only, one request/Signature/Activity operation. Constructed only by the
 * existing DeviceKeyStore after its exact registered APPROVAL key inspection.
 * No Signature/CryptoObject accessor, generic sign(bytes), JS, receiver or Binder
 * endpoint exists. Callbacks go to the existing native actor, never a WebView.
 *
 * ROOT's actor must present only the actual resumed Activity, then defer complete
 * until that SAME Activity resumes after credential UI. It must call cancel on
 * destruction/recreation, request withdrawal, expiry or owner failure, NOT simply
 * pause/stop. No authentication state survives process death or Activity change.
 *
 * plan.cancel/isCancelled are bounded atomic-only Rust calls (no IO, callback or
 * owner admission). Other plan/attempt methods and all key work are worker-only.
 */
internal class NativeApprovalOperation internal constructor(
    private val appContext: Context,
    private val plan: NativeApprovalPlan,
    signature: Signature,
    private val deadlineNanos: Long,
    preparedAtNanos: Long,
    private val recheckKey: () -> KeyStoreOutcome<Unit>,
    private val releaseSlot: (NativeApprovalOperation) -> Unit,
) {
    private val lock = Any()
    private val policy = ApprovalOperationPolicy(deadlineNanos, preparedAtNanos, signature)
    private var signature: Signature? = signature
    private val cancellation = CancellationSignal()
    private val main = Handler(Looper.getMainLooper())
    private var authenticatedSink: ((NativeApprovalOperation, Activity) -> Unit)? = null
    private var terminalSink: ((NativeApprovalOperation, ApprovalOperationError) -> Unit)? = null
    private var promptPending = false
    private var cancelDispatchPending = false
    private var cancellationConfirmed = false
    private var retirementConfirmed = false
    private var signed = false
    private var releasing = false
    private var released = false
    private val expiry = Runnable { cancel(ApprovalOperationError.EXPIRED) }

    /** Value means an OS prompt was submitted, never that authentication passed. */
    fun present(
        host: Activity,
        onAuthenticated: (NativeApprovalOperation, Activity) -> Unit,
        onTerminal: (NativeApprovalOperation, ApprovalOperationError) -> Unit,
    ): ApprovalOperationOutcome<Unit> {
        if (!onMain()) return ApprovalOperationOutcome.Failure(ApprovalOperationError.WRONG_THREAD)
        if (!policy.isPrepared()) return ApprovalOperationOutcome.Failure(policy.terminalError() ?: ApprovalOperationError.ALREADY_USED)
        if (!usableHost(host)) {
            cancel(ApprovalOperationError.HOST_UNAVAILABLE)
            return ApprovalOperationOutcome.Failure(ApprovalOperationError.HOST_UNAVAILABLE)
        }
        val current = try {
            if (plan.isCancelled()) {
                cancel()
                return ApprovalOperationOutcome.Failure(ApprovalOperationError.CANCELLED)
            }
            synchronized(lock) {
                val error = policy.present(host, SystemClock.elapsedRealtimeNanos())
                if (error != null) return@synchronized ApprovalOperationOutcome.Failure(error)
                authenticatedSink = onAuthenticated
                terminalSink = onTerminal
                signature?.let { ApprovalOperationOutcome.Value(it) }
                    ?: ApprovalOperationOutcome.Failure(ApprovalOperationError.ALREADY_USED)
            }
        } catch (_: Exception) {
            cancel(ApprovalOperationError.NATIVE_UNAVAILABLE)
            return ApprovalOperationOutcome.Failure(ApprovalOperationError.NATIVE_UNAVAILABLE)
        }
        val retainedSignature = when (current) {
            is ApprovalOperationOutcome.Value -> current.value
            is ApprovalOperationOutcome.Failure -> {
                // A duplicate present must not replace callbacks/Activity or restart.
                if (current.error != ApprovalOperationError.ALREADY_USED) cancel(current.error)
                return current
            }
        }
        try {
            val now = SystemClock.elapsedRealtimeNanos()
            val beforePrompt = policy.presentationCheck(now)
            if (beforePrompt != null) {
                cancel(beforePrompt)
                return ApprovalOperationOutcome.Failure(beforePrompt)
            }
            // Handler uses uptime: this is a wakeup only, not suspend/expiry proof.
            // Authentication progress and worker phases check elapsed time afresh.
            val remaining = deadlineNanos - now
            val delayMillis = remaining / 1_000_000 + if (remaining % 1_000_000 == 0L) 0 else 1
            if (!main.postDelayed(expiry, delayMillis)) {
                cancel(ApprovalOperationError.NATIVE_UNAVAILABLE)
                return ApprovalOperationOutcome.Failure(ApprovalOperationError.NATIVE_UNAVAILABLE)
            }
            val prompt = BiometricPrompt.Builder(host)
                .setTitle(AppLanguage.text(host, R.string.approval_auth_title))
                .setDescription(AppLanguage.text(host, R.string.approval_auth_description))
                .setAllowedAuthenticators(ALLOWED_AUTHENTICATORS)
                .setConfirmationRequired(true)
                // DEVICE_CREDENTIAL supplies its own system button. Never set a
                // negative button or replace the OS PIN/pattern/password entry.
                .build()
            synchronized(lock) {
                if (policy.isTerminal()) return ApprovalOperationOutcome.Failure(policy.terminalError() ?: ApprovalOperationError.CANCELLED)
                promptPending = true
            }
            prompt.authenticate(BiometricPrompt.CryptoObject(retainedSignature), cancellation, host.mainExecutor,
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) = authenticated(host, result)
                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                        // Never retain/log/display errString or any raw Android code.
                        synchronized(lock) { promptPending = false }
                        if (!policy.isAwaitingAuthentication()) {
                            releaseIfQuiescent()
                            return
                        }
                        val category = when (errorCode) {
                            BiometricPrompt.BIOMETRIC_ERROR_CANCELED,
                            BiometricPrompt.BIOMETRIC_ERROR_USER_CANCELED -> ApprovalOperationError.AUTHENTICATION_CANCELLED
                            else -> ApprovalOperationError.AUTHENTICATION_ERROR
                        }
                        cancel(category)
                    }
                    override fun onAuthenticationFailed() {
                        authenticationFailed()
                    }
                })
            return ApprovalOperationOutcome.Value(Unit)
        } catch (_: Exception) {
            // authenticate may have partially submitted before throwing. Keep the
            // slot quarantined until an actual terminal callback if submitted.
            cancel(ApprovalOperationError.AUTHENTICATION_UNAVAILABLE)
            return ApprovalOperationOutcome.Failure(ApprovalOperationError.AUTHENTICATION_UNAVAILABLE)
        }
    }

    private fun authenticationFailed() {
        // A mismatch remains nonterminal while the ORIGINAL lifetime is live;
        // neither the deadline nor the initialized Signature is reset.
        if (!policy.isAwaitingAuthentication()) return
        if (!onMain()) { cancel(ApprovalOperationError.NATIVE_UNAVAILABLE); return }
        try {
            if (plan.isCancelled()) { cancel(); return }
            policy.presentationCheck(SystemClock.elapsedRealtimeNanos())?.let { cancel(it) }
        } catch (_: Exception) { cancel(ApprovalOperationError.NATIVE_UNAVAILABLE) }
    }

    /** The ONLY production authentication-success transition. */
    private fun authenticated(host: Activity, result: BiometricPrompt.AuthenticationResult) {
        synchronized(lock) { promptPending = false }
        if (!policy.isAwaitingAuthentication()) {
            // Duplicate/late callbacks cannot cancel a prepared Rust submission
            // after the successful callback has already closed this OS phase.
            releaseIfQuiescent()
            return
        }
        if (!onMain() || !usableHost(host)) {
            cancel(ApprovalOperationError.HOST_UNAVAILABLE)
            return
        }
        try {
            if (plan.isCancelled()) { cancel(); return }
            val sink = synchronized(lock) {
                val error = policy.authenticated(host, result.cryptoObject?.signature, SystemClock.elapsedRealtimeNanos())
                if (error != null) return@synchronized null
                // Equality is actual object identity in policy, not algorithm,
                // public key equality, an auth type or a supplied success boolean.
                authenticatedSink.also { authenticatedSink = null }
            }
            if (sink != null) sink(this, host)
            else if (policy.terminalError() != null) cancel(policy.terminalError() ?: ApprovalOperationError.CANCELLED)
        } catch (_: Exception) {
            cancel(ApprovalOperationError.NATIVE_UNAVAILABLE)
        } finally {
            releaseIfQuiescent()
        }
    }

    /**
     * Worker-only, called once by the native actor with a Rust-minted attempt.
     * Returns DER to that actor only; it must consume/clear it, recheck fresh
     * native time, finish in Rust, then call releaseAfterFinish. This is NOT a PC
     * approval result. The original initialized Signature is never reinitialized.
     */
    fun complete(attempt: NativeApprovalAttempt): ApprovalOperationOutcome<ByteArray> {
        if (onMain()) return ApprovalOperationOutcome.Failure(ApprovalOperationError.WRONG_THREAD)
        if (!policy.isAwaitingSigning()) return ApprovalOperationOutcome.Failure(policy.terminalError() ?: ApprovalOperationError.ALREADY_USED)
        var statement: ByteArray? = null
        val buffer = ByteArray(ApprovalOperationBounds.MAX_DER_BYTES)
        var entered = false
        try {
            if (!attempt.belongsTo(plan)) return failed(ApprovalOperationError.INVALID_PLAN)
            if (plan.isCancelled() || attempt.isCancelled()) return failed(ApprovalOperationError.CANCELLED)
            val started = synchronized(lock) { policy.beginSigning(SystemClock.elapsedRealtimeNanos()) }
            if (started != null) {
                // Do not disturb the existing sign invocation on a duplicate.
                return if (started == ApprovalOperationError.ALREADY_USED) ApprovalOperationOutcome.Failure(started)
                    else failed(started)
            }
            entered = true
            statement = attempt.signingBytes()
            if (!ApprovalOperationBounds.validSigningBytes(statement)) return failed(ApprovalOperationError.INVALID_SIGNING_INPUT)
            when (val checked = recheckKey()) {
                is KeyStoreOutcome.Failure -> {
                    cancel(ApprovalOperationError.KEYS_UNAVAILABLE)
                    return ApprovalOperationOutcome.Failure(ApprovalOperationError.KEYS_UNAVAILABLE, checked.error)
                }
                is KeyStoreOutcome.Value -> Unit
            }
            if (plan.isCancelled() || attempt.isCancelled()) return failed(ApprovalOperationError.CANCELLED)
            val beforeSign = synchronized(lock) { policy.signingCheck(SystemClock.elapsedRealtimeNanos()) }
            if (beforeSign != null) return failed(beforeSign)
            val retained = synchronized(lock) { signature } ?: return failed(ApprovalOperationError.ALREADY_USED)
            // No prehash, alternate mode or unbounded returned signature array.
            retained.update(statement)
            val length = retained.sign(buffer, 0, buffer.size)
            if (!ApprovalOperationBounds.validDerLength(length)) return failed(ApprovalOperationError.SIGNING_FAILED)
            if (plan.isCancelled() || attempt.isCancelled()) return failed(ApprovalOperationError.CANCELLED)
            val completed = synchronized(lock) {
                val error = policy.finishSigning(SystemClock.elapsedRealtimeNanos())
                if (error != null) ApprovalOperationOutcome.Failure(error)
                else {
                    // This locked result gate linearizes against local cancel.
                    // Rust must still reject cancellation occurring afterwards.
                    signed = true
                    ApprovalOperationOutcome.Value(buffer.copyOf(length))
                }
            }
            if (completed is ApprovalOperationOutcome.Failure) return failed(completed.error)
            // Rust validates strict DER and normalizes high-S during verification;
            // Android may legitimately return either S. Never normalize/reject it here.
            return completed
        } catch (_: Exception) {
            return failed(ApprovalOperationError.SIGNING_FAILED)
        } finally {
            statement?.fill(0)
            buffer.fill(0)
            if (entered) synchronized(lock) { policy.signingExited() }
            releaseIfQuiescent()
        }
    }

    /**
     * Downward-only, any thread. Invalidate native/local state BEFORE asking the
     * OS to cancel. No denial is fabricated. Retry is allowed only for cleanup;
     * no path makes this operation live again or reinitializes its Signature.
     */
    fun cancel() = cancel(ApprovalOperationError.CANCELLED)

    private fun cancel(reason: ApprovalOperationError) {
        synchronized(lock) {
            if (released) return
            policy.cancel(reason)
        }
        try {
            plan.cancel()
            synchronized(lock) { cancellationConfirmed = true }
        } catch (_: Exception) {
            // The local gate is closed; uncertain Rust cleanup keeps the slot.
        }
        val dispatch = synchronized(lock) {
            if (!promptPending || cancelDispatchPending) false
            else { cancelDispatchPending = true; true }
        }
        if (dispatch) {
            val action = Runnable {
                try { cancellation.cancel() }
                catch (_: Exception) { /* No claim of OS cancellation success. */ }
                finally { synchronized(lock) { cancelDispatchPending = false }; releaseIfQuiescent() }
            }
            if (onMain()) action.run()
            else if (!main.post(action)) synchronized(lock) { cancelDispatchPending = false }
        }
        releaseIfQuiescent()
    }

    /**
     * Native actor calls ONLY after Rust finish consumed/discarded the DER.
     * Rust's atomic isCancelled also reports its separate irreversible native-
     * phase-closed flag. No plan.cancel call here: that would invalidate a valid
     * prepared transport submission sharing the plan's cancellation token.
     */
    fun releaseAfterFinish(): ApprovalOperationOutcome<Unit> {
        if (isQuiescent()) return ApprovalOperationOutcome.Value(Unit)
        val finished = synchronized(lock) { signed && policy.isTerminal() && policy.isQuiescent() }
        if (!finished) return ApprovalOperationOutcome.Failure(ApprovalOperationError.ALREADY_USED)
        val nativeClosed = try { plan.isCancelled() } catch (_: Exception) { false }
        if (!nativeClosed) return ApprovalOperationOutcome.Failure(ApprovalOperationError.CLEANUP_PENDING)
        synchronized(lock) { retirementConfirmed = true }
        releaseIfQuiescent()
        return if (isQuiescent()) ApprovalOperationOutcome.Value(Unit)
            else ApprovalOperationOutcome.Failure(ApprovalOperationError.CLEANUP_PENDING)
    }

    /** True only after local slot cleanup; not proof of OS/PC approval. */
    fun isQuiescent(): Boolean = synchronized(lock) { released }

    private fun failed(error: ApprovalOperationError): ApprovalOperationOutcome.Failure {
        cancel(error)
        return ApprovalOperationOutcome.Failure(error)
    }

    private fun releaseIfQuiescent() {
        val delivery = synchronized(lock) {
            if (released || releasing || !policy.isQuiescent() || promptPending || cancelDispatchPending ||
                (!cancellationConfirmed && !retirementConfirmed)) return
            releasing = true
            signature = null
            authenticatedSink = null
            val result = if (!signed) terminalSink?.let { it to (policy.terminalError() ?: ApprovalOperationError.CANCELLED) } else null
            terminalSink = null
            result
        }
        main.removeCallbacks(expiry)
        // Never acquire the key registry lock while holding this operation lock.
        releaseSlot(this)
        synchronized(lock) { released = true; releasing = false }
        if (delivery != null) {
            val action = Runnable { try { delivery.first(this, delivery.second) } catch (_: Exception) { /* Actor owns delivery recovery. */ } }
            if (onMain()) action.run() else main.post(action)
        }
    }

    private fun onMain(): Boolean = Looper.myLooper() == Looper.getMainLooper()
    private fun usableHost(host: Activity): Boolean = try {
        host.applicationContext === appContext && !host.isFinishing && !host.isDestroyed
    } catch (_: Exception) { false }
    override fun toString(): String = "NativeApprovalOperation([redacted], not_pc_approval)"

    companion object {
        internal const val ALLOWED_AUTHENTICATORS: Int =
            ApprovalOperationBounds.ALLOWED_AUTHENTICATORS
    }
}
