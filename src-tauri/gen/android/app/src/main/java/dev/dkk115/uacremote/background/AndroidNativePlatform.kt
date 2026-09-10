// SPDX-License-Identifier: GPL-2.0-or-later

package dev.dkk115.uacremote.background

import android.app.Application
import android.app.NotificationManager
import android.os.Looper
import dev.dkk115.uacremote.nativecore.BridgeException
import dev.dkk115.uacremote.nativecore.NativeClock
import dev.dkk115.uacremote.nativecore.NativePlatform
import dev.dkk115.uacremote.nativecore.NativeLocalKeySet
import dev.dkk115.uacremote.nativecore.NativeApprovalPlan
import dev.dkk115.uacremote.nativecore.NativeRequestSelection
import dev.dkk115.uacremote.nativecore.NativeCertificateVerify
import dev.dkk115.uacremote.nativecore.NativeTransportBinding
import dev.dkk115.uacremote.nativecore.NativeDenialScope
import dev.dkk115.uacremote.nativecore.NativeDenialAttempt
import dev.dkk115.uacremote.nativecore.NativeApprovalDrainState
import dev.dkk115.uacremote.nativecore.NativeDenialOperationState
import dev.dkk115.uacremote.nativecore.NativePendingRequest
import dev.dkk115.uacremote.nativecore.NativePresentationClock
import dev.dkk115.uacremote.nativecore.NativeRequestPresentation
import dev.dkk115.uacremote.nativecore.NativeRequestAlert
import dev.dkk115.uacremote.nativecore.NativeRequestSinkOutcome
import dev.dkk115.uacremote.nativecore.NativeKeyCreationRequest
import dev.dkk115.uacremote.nativecore.NativeKeyCreationInput
import dev.dkk115.uacremote.nativecore.NativeCreatedKeyEvidence
import dev.dkk115.uacremote.security.DeviceKeyStore
import dev.dkk115.uacremote.security.KeyStoreOutcome
import dev.dkk115.uacremote.security.ReopenKeySetDescriptor
import dev.dkk115.uacremote.security.ClientCertificateVerifyPolicy
import dev.dkk115.uacremote.security.NativeTransportSigner
import dev.dkk115.uacremote.security.TransportSignerOutcome
import dev.dkk115.uacremote.security.NativeDenialOperation
import dev.dkk115.uacremote.security.KeyCreationRequest
import dev.dkk115.uacremote.security.DeviceKeyRole
import dev.dkk115.uacremote.security.NativeCreationEvidence

/**
 * Generated-trait adapter only. The Application owner calls it from a bounded
 * background worker. No Activity, app startup, enrollment, permission request,
 * notification posting or authentication takes place at construction.
 */
internal class AndroidNativePlatform(application: Application) : NativePlatform {
    private val application = application
    private val environment = NativeEnvironment(application)
    private val legacy = LegacyPolicyObservation(application)
    private val keyStore = DeviceKeyStore(application)
    private val creationActive = java.util.concurrent.atomic.AtomicBoolean(false)
    // Reuse existing bounded generated-wrapper cleanup accounting. The only
    // native key/reference registry remains DeviceKeyStore's original owner.
    private val creationArguments = DenialCloseCursor(2)
    @Volatile private var requestProgress: (() -> Unit)? = null
    @Volatile private var requestChanged: (() -> Unit)? = null
    @Volatile private var timeChanged: (() -> Unit)? = null
    @Volatile private var requestCleanup: (() -> Unit)? = null
    private val presentation: NativePresentationClockSource = NativePresentationClockSource {
        requests.invalidateTime()
        timeChanged?.invoke()
    }
    internal val requests: NativeRequestRegistry = NativeRequestRegistry(application, presentation,
        { requestChanged?.invoke() }, { requestCleanup?.invoke() })

    internal fun bindRequests(progress: () -> Unit, changed: () -> Unit, temporal: () -> Unit, cleanup: () -> Unit) {
        check(requestProgress == null)
        requestProgress = progress; requestChanged = changed; timeChanged = temporal; requestCleanup = cleanup
    }
    override fun intakeProgress() { requestProgress?.invoke() ?: throw BridgeException.NativeUnavailable() }
    override fun presentationClock(): NativePresentationClock = presentation.observe()
    override fun publishPendingRequest(request: NativePendingRequest, intent: NativeRequestPresentation, alert: NativeRequestAlert): NativeRequestSinkOutcome =
        requests.publish(request, intent, alert)
    internal fun refreshPresentationClock() { clock() }
    internal fun invalidateRequestTime() { presentation.invalidate() }
    internal fun stopRequests() { requests.stop() }
    internal fun closeRequestClock() { presentation.close() }
    internal fun secureLockConfigured(): Boolean = try {
        application.getSystemService(android.app.KeyguardManager::class.java)?.isDeviceSecure ?: throw BridgeException.NativeUnavailable()
    } catch (_: Exception) { throw BridgeException.NativeUnavailable() }
    private var withdrawal: ((NativeRequestSelection) -> Unit)? = null
    private var clearHeldApprovals: (() -> Unit)? = null
    private val transportLock = Any()
    private val transports = LinkedHashMap<ULong, TransportEntry>()
    private val failedTransportArguments = ArrayList<AutoCloseable>()
    @Volatile private var transportStopping = false
    private var transportCleanupUncertain = false
    private var denials: DenialJobs? = null
    private val unboundDenialArguments = DenialCloseCursor()

    internal fun bindDenials(owner: DenialJobs) { check(denials == null); denials = owner }
    internal fun registerDenialOperation(attempt: NativeDenialAttempt, progress: () -> Unit): NativeDenialOperation =
        keyStore.registerDenialOperation(attempt, progress)
    internal fun signDenial(attempt: NativeDenialAttempt): ByteArray = keyStore.signDenial(attempt)
    internal fun releaseDenialOperation(operation: NativeDenialOperation): Boolean = keyStore.releaseDenialOperation(operation)
    internal fun retryUnboundDenialCleanup(): Boolean = unboundDenialArguments.retryOnce()
    internal fun denialReferencesClear(): Boolean = unboundDenialArguments.complete() && denials?.permitsKeyReferenceCleanup() != false

    override fun advanceApprovalDrainForDenial(scope: NativeDenialScope): NativeApprovalDrainState =
        denialRegistry(scope).advance(scope)
    override fun observeDenialOperation(attempt: NativeDenialAttempt): NativeDenialOperationState =
        denialRegistry(attempt).observe(attempt)
    override fun releaseDenialScope(scope: NativeDenialScope) = denialRegistry(scope).release(scope)

    private fun denialRegistry(argument: AutoCloseable): DenialDrainRegistry {
        val owner = denials
        if (Looper.myLooper() != Looper.getMainLooper() && owner != null) return owner.registry
        try { unboundDenialArguments.closeOrRetain(argument) } catch (_: Exception) { }
        throw BridgeException.NativeUnavailable()
    }

    // Only native opaque identities index this map. IDs select a candidate;
    // sameBinding/belongsTo must ALSO succeed before any native key operation.
    private class TransportEntry(val binding: NativeTransportBinding) {
        var signer: NativeTransportSigner? = null
        var input: NativeCertificateVerify? = null
        var releaseArgument: NativeTransportBinding? = null
        var closing = false
        var bindingClosed = false
        override fun toString(): String = "TransportEntry([redacted])"
    }

    override fun prepareTransportSigner(binding: NativeTransportBinding) {
        requireTransportWorker()
        synchronized(transportLock) {
            var retained = false
            try {
                val id = binding.referenceId()
                if (id == 0uL || transportStopping) throw BridgeException.NativeUnavailable()
                val existing = transports[id]
                if (existing != null) {
                    retained = binding === existing.binding
                    // Repeated prepare is idempotent only for the exact healthy
                    // binding. It never constructs another signer or reopens keys.
                    if (!binding.sameBinding(existing.binding) || existing.closing || existing.signer == null || binding.isClosed()) {
                        throw BridgeException.NativeUnavailable()
                    }
                    return@synchronized
                }
                if (transports.size >= ClientCertificateVerifyPolicy.MAX_SIGNERS) throw BridgeException.NativeUnavailable()
                val entry = TransportEntry(binding)
                transports[id] = entry // Cleanup obligation precedes native preparation.
                retained = true
                if (binding.isClosed()) { entry.closing = true; throw BridgeException.NativeUnavailable() }
                when (val prepared = keyStore.prepareTransportSigner(binding)) {
                    is TransportSignerOutcome.Value -> entry.signer = prepared.value
                    is TransportSignerOutcome.Failure -> { entry.closing = true; throw BridgeException.LocalKeysUnavailable() }
                }
                if (binding.isClosed()) { entry.closing = true; throw BridgeException.NativeUnavailable() }
            } catch (_: Exception) {
                // Rust closes its binding before its one release callback. A
                // partially prepared entry remains here even when this throws.
                throw BridgeException.NativeUnavailable()
            } finally {
                if (!retained) closeTemporaryTransportArgument(binding)
            }
        }
    }

    override fun signClientCertificateVerify(input: NativeCertificateVerify): ByteArray {
        requireTransportWorker()
        synchronized(transportLock) {
            var entry: TransportEntry? = null
            var der: ByteArray? = null
            var accepted = false
            try {
                if (transportStopping) throw BridgeException.NativeUnavailable()
                val selected = transports[input.bindingId()] ?: throw BridgeException.NativeUnavailable()
                if (!input.belongsTo(selected.binding) || selected.closing || selected.input != null || selected.bindingClosed) {
                    throw BridgeException.NativeUnavailable()
                }
                entry = selected
                selected.input = input
                val signer = selected.signer ?: throw BridgeException.NativeUnavailable()
                when (val signed = signer.sign(input)) {
                    is TransportSignerOutcome.Failure -> { selected.closing = true; throw BridgeException.NativeUnavailable() }
                    is TransportSignerOutcome.Value -> der = signed.value
                }
                if (transportStopping || selected.binding.isClosed() || input.isCancelled()) throw BridgeException.NativeUnavailable()
                accepted = true
            } catch (_: Exception) {
                entry?.closing = true
            } finally {
                // The provider has returned before any generated input closes.
                // On close failure the EXACT wrapper stays for explicit cleanup.
                val selected = entry
                if (selected != null) {
                    try { input.close(); selected.input = null }
                    catch (_: Exception) { selected.closing = true; accepted = false }
                    if (selected.closing) {
                        try { selected.binding.closeBinding() } catch (_: Exception) { /* retained cleanup obligation */ }
                        selected.signer?.close()
                    }
                } else {
                    try { closeTemporaryTransportArgument(input) }
                    catch (_: Exception) { accepted = false }
                }
            }
            val result = der
            // Temporary-handle cleanup can itself cross native code. Recheck the
            // retained binding/admission afterwards, not the now-closed input.
            if (accepted) {
                accepted = try { !transportStopping && entry?.binding?.isClosed() == false }
                catch (_: Exception) { false }
            }
            if (!accepted || result == null) {
                result?.fill(0)
                throw BridgeException.NativeUnavailable()
            }
            return result
        }
    }

    override fun releaseTransportSigner(binding: NativeTransportBinding) {
        requireTransportWorker()
        synchronized(transportLock) {
            var retainedArgument = false
            try {
                val id = binding.referenceId()
                val entry = transports[id]
                if (entry == null) {
                    if (!binding.isClosed()) throw BridgeException.NativeUnavailable()
                    return@synchronized // No owned signer; still close this argument below.
                }
                retainedArgument = binding === entry.binding
                if (!binding.sameBinding(entry.binding) || !binding.isClosed()) throw BridgeException.NativeUnavailable()
                retainedArgument = true
                if (binding !== entry.binding) {
                    // Rust invokes release at most ONCE per binding. Retries are
                    // local cleanup of this retained argument, not fresh wrappers.
                    if (entry.releaseArgument != null && entry.releaseArgument !== binding) {
                        retainedArgument = false
                        throw BridgeException.NativeUnavailable()
                    }
                    entry.releaseArgument = binding
                }
                entry.closing = true
                if (!cleanupTransportEntry(entry) || failedTransportArguments.isNotEmpty() || transportCleanupUncertain) {
                    throw BridgeException.NativeUnavailable()
                }
                transports.remove(id)
            } catch (_: Exception) {
                throw BridgeException.NativeUnavailable()
            } finally {
                if (!retainedArgument) closeTemporaryTransportArgument(binding)
            }
        }
    }

    /** Called with transportLock. No actor dispatch or Rust store mutex is held. */
    private fun cleanupTransportEntry(entry: TransportEntry): Boolean {
        entry.closing = true
        try {
            if (!entry.bindingClosed) entry.binding.closeBinding()
            val signer = entry.signer
            if (signer != null && (signer.close() is TransportSignerOutcome.Failure || !signer.isQuiescent())) return false
            entry.input?.let { it.close(); entry.input = null }
            entry.releaseArgument?.let { it.close(); entry.releaseArgument = null }
            if (!entry.bindingClosed) {
                entry.binding.close()
                entry.bindingClosed = true // Only after close returned successfully.
            }
            return true
        } catch (_: Exception) { return false }
    }

    private fun closeTemporaryTransportArgument(argument: AutoCloseable) {
        // A caller can pass the same Java wrapper rather than a fresh callback
        // wrapper. Only its existing cleanup record may close that object.
        if (transports.values.any { it.binding === argument || it.input === argument || it.releaseArgument === argument } ||
            failedTransportArguments.any { it === argument }) return
        try { argument.close() }
        catch (_: Exception) {
            transportStopping = true
            // Root bounds live bindings to32, one sign and one release argument
            // each; no retry mints more wrappers after error. Malformed callback
            // routing can therefore retain at most64 temporary cleanup handles.
            if (failedTransportArguments.none { it === argument }) {
                if (failedTransportArguments.size >= ClientCertificateVerifyPolicy.MAX_SIGNERS * 2) transportCleanupUncertain = true
                else failedTransportArguments.add(argument)
            }
            throw BridgeException.NativeUnavailable()
        }
    }

    private fun closeAllTransportSigners() {
        requireTransportWorker()
        // Close native admission before waiting for an in-flight direct callback.
        // Its final gate observes this volatile flag and discards any late DER.
        transportStopping = true
        synchronized(transportLock) {
            val iterator = transports.entries.iterator()
            while (iterator.hasNext()) {
                val entry = iterator.next().value
                if (cleanupTransportEntry(entry)) iterator.remove()
            }
            val arguments = failedTransportArguments.iterator()
            while (arguments.hasNext()) {
                try { arguments.next().close(); arguments.remove() }
                catch (_: Exception) { /* retain exactly the failed handle for retry */ }
            }
            if (transports.isNotEmpty() || failedTransportArguments.isNotEmpty() || transportCleanupUncertain) {
                throw BridgeException.NativeUnavailable()
            }
        }
    }

    private fun requireTransportWorker() {
        if (Looper.myLooper() == Looper.getMainLooper()) throw BridgeException.NativeUnavailable()
    }

    internal fun bindWithdrawal(receiver: (NativeRequestSelection) -> Unit, clear: () -> Unit) {
        check(withdrawal == null)
        withdrawal = receiver
        clearHeldApprovals = clear
    }
    internal fun prepareApproval(plan: NativeApprovalPlan) = keyStore.prepareApproval(plan)

    override fun withdrawRequests(requests: List<NativeRequestSelection>) {
        if (Looper.myLooper() == Looper.getMainLooper() || requests.size > 1024) throw BridgeException.NativeUnavailable()
        val manager = application.getSystemService(NotificationManager::class.java) ?: throw BridgeException.NativeUnavailable()
        try {
            for (request in requests) {
                // Invalidate any held auth attempt before the OS notification IO.
                withdrawal?.invoke(request)
                denials?.withdraw(request)
                this.requests.withdraw(request)
                manager.cancel(NativeRequestIdentity.notificationTag(request), 1)
            }
        } catch (_: Exception) { throw BridgeException.NativeUnavailable() }
    }

    override fun legacyPolicyDocument(): String? = legacy.legacyPolicyDocument()
    override fun hasDeviceKeys(): Boolean = legacy.hasDeviceKeys()

    override fun createLocalKeySet(request: NativeKeyCreationRequest): NativeCreatedKeyEvidence {
        if (!creationActive.compareAndSet(false, true)) {
            try { creationArguments.closeOrRetain(request) } catch (_: Exception) { }
            throw BridgeException.LocalKeysReconciliationRequired()
        }
        var input: NativeKeyCreationInput? = null
        try {
            if (Looper.myLooper() == Looper.getMainLooper() || !creationArguments.complete()) {
                throw BridgeException.LocalKeysReconciliationRequired()
            }
            // Rust minted this opaque one-shot request only AFTER its actual
            // Preparing commit. takeInput freshly checks original owner/time;
            // a delayed callback cannot convert a closed/expired bool to a grant.
            val original = request.takeInput()
            input = original
            if (!NativeCreationEvidence.validInput(original)) throw BridgeException.InvalidObservation()
            val creation = keyValue(KeyCreationRequest.fromTrustedRust(original.handle, original.challenge, request::checkCurrent))
            request.checkCurrent()
            val created = keyValue(keyStore.createKeySet(creation))
            // Only re-inspect the exact just-created registered references.
            // No reopen/create/retry fallback, and no native wrapper in reply.
            val material = DeviceKeyRole.values().associateWith { role ->
                keyValue(keyStore.inspectPublicMaterial(created.reference(role)))
            }
            request.checkCurrent()
            return NativeCreationEvidence.copyObserved(original, created.registration.descriptor, material)
        } catch (_: Exception) {
            // Rust retains Preparing/reconciliation and the existing Application
            // cleanup owner. Never delete aliases after uncertain callback/IO.
            throw BridgeException.LocalKeysReconciliationRequired()
        } finally {
            input?.handle?.fill(0)
            input?.challenge?.fill(0)
            input?.ceremonyNonce?.fill(0)
            try { creationArguments.closeOrRetain(request) }
            catch (_: Exception) { throw BridgeException.LocalKeysReconciliationRequired() }
            finally { creationActive.set(false) }
        }
    }

    override fun reopenLocalKeySets(keys: List<NativeLocalKeySet>) {
        if (Looper.myLooper() == Looper.getMainLooper() || keys.isEmpty() || keys.size > 32) {
            throw BridgeException.LocalKeysUnavailable()
        }
        // This is committed LOCAL metadata, not paired-device authorization.
        // Copy/validate the whole tuple list before any reference publication.
        val descriptors = keys.map { key ->
            keyValue(ReopenKeySetDescriptor.fromTrustedStorage(
                key.handle, key.approvalSpki, key.denialSpki, key.transportSpki,
            ))
        }
        val handles = descriptors.map { it.copyHandle() }
        try {
            keyValue(keyStore.validateRecordedNamespace(handles))
            for (descriptor in descriptors) keyValue(keyStore.reopenExistingKeySet(descriptor))
            keyValue(keyStore.validateRecordedNamespace(handles))
        } catch (_: Exception) {
            // Close this adapter's references only. A failed close remains
            // retryable through the Application-retained adapter; never touch
            // aliases/snapshot bytes or an unrelated instance's registrations.
            keyStore.closeReferences()
            throw BridgeException.LocalKeysUnavailable()
        }
    }

    override fun releaseLocalKeyReferences() {
        if (!CreationArgumentCleanupPolicy.ready(creationActive, creationArguments)) {
            throw BridgeException.NativeUnavailable()
        }
        if (denials?.permitsKeyReferenceCleanup() == false || !unboundDenialArguments.complete()) {
            throw BridgeException.NativeUnavailable()
        }
        closeAllTransportSigners()
        keyValue(keyStore.closeReferences())
    }

    /** Only the Application's existing EXPLICIT shutdown/retry branch calls
     * this. Ordinary Rust failure cleanup may observe, never grant this retry. */
    internal fun retryCreationArgumentCleanup(): Boolean {
        return CreationArgumentCleanupPolicy.retryExplicitly(creationActive, creationArguments)
    }

    private fun <T> keyValue(result: KeyStoreOutcome<T>): T = when (result) {
        is KeyStoreOutcome.Value -> result.value
        is KeyStoreOutcome.Failure -> throw BridgeException.LocalKeysUnavailable()
    }

    override fun unixMillis(): ULong {
        if (Looper.myLooper() == Looper.getMainLooper()) throw BridgeException.NativeUnavailable()
        val observed = System.currentTimeMillis()
        if (observed < 0) throw BridgeException.NativeUnavailable()
        // Actual phone display/retention time only. Rust validates its range;
        // authorization and expiry use the separate elapsedRealtimeNanos clock.
        return observed.toULong()
    }

    override fun stateDirectory(): String = when (val result = environment.controllerDirectory()) {
        is NativeEnvironmentOutcome.Value -> result.value.canonicalPath
        is NativeEnvironmentOutcome.Failure -> throw BridgeException.NativeUnavailable()
    }

    override fun clock(): NativeClock {
        val observed = when (val result = environment.observe()) {
            is NativeEnvironmentOutcome.Value -> result.value
            is NativeEnvironmentOutcome.Failure -> throw BridgeException.NativeUnavailable()
        }
        if (observed.credentialStorage != CredentialStorageState.AVAILABLE) {
            throw BridgeException.NativeUnavailable()
        }
        presentation.warm(observed.bootCount)
        // Values have already passed native shape/coherence checks. Rust checks
        // them again and owns all schedule/expiry/recovery decisions. This sample
        // is not a post-I/O action permit; native dispatch must observe time again.
        return NativeClock(
            bootCount = observed.bootCount.toUInt(),
            monotonicNanos = observed.elapsedRealtimeNanos.toULong(),
            weekday = observed.weekdayMondayZero.toUByte(),
            minute = observed.minuteOfDay.toUShort(),
        )
    }

    override fun clearRequestNotifications() {
        if (Looper.myLooper() == Looper.getMainLooper()) throw BridgeException.NativeUnavailable()
        try {
            clearHeldApprovals?.invoke()
            requests.clear()
            val manager = application.getSystemService(NotificationManager::class.java)
                ?: throw BridgeException.NativeUnavailable()
            for (notification in manager.activeNotifications) {
                if (notification.packageName == application.packageName &&
                    notification.notification.channelId == REQUEST_CHANNEL &&
                    notification.tag?.startsWith(REQUEST_TAG_PREFIX) == true) {
                    manager.cancel(notification.tag, notification.id)
                }
            }
        } catch (_: Exception) {
            // No raw Android exception/path/provider message crosses UniFFI.
            throw BridgeException.NativeUnavailable()
        }
    }

    override fun toString(): String = "AndroidNativePlatform(application_background_adapter)"

    private companion object {
        // Internal ownership namespace, never a user-facing channel label.
        const val REQUEST_CHANNEL = "uac_requests"
        const val REQUEST_TAG_PREFIX = "request:"
    }
}
