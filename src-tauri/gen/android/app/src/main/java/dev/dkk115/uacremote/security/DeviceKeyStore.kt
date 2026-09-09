// SPDX-License-Identifier: GPL-2.0-or-later

package dev.dkk115.uacremote.security

import android.app.KeyguardManager
import android.content.Context
import android.os.Build
import android.os.Looper
import android.os.UserManager
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.UserNotAuthenticatedException
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.UnrecoverableKeyException
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.concurrent.atomic.AtomicBoolean

/** Closed, purpose-separated identity roles. These names are not user input. */
internal enum class DeviceKeyRole { APPROVAL, DENIAL, TRANSPORT }

internal enum class DeviceLockState { CONFIGURED, MISSING, UNAVAILABLE }

internal enum class HardwareProtection {
    TEE,
    STRONGBOX,
    /** API 30's positive hardware observation cannot distinguish TEE from SE. */
    LEGACY_SECURE_HARDWARE,
    SOFTWARE,
    UNAVAILABLE,
}

internal enum class DeviceKeyError {
    INVALID_ENROLLMENT_HANDLE,
    INVALID_ATTESTATION_CHALLENGE,
    REQUEST_ALREADY_CONSUMED,
    WRONG_THREAD,
    CREDENTIAL_STORAGE_LOCKED,
    CREDENTIAL_STORAGE_UNAVAILABLE,
    LOCK_MISSING,
    LOCK_UNAVAILABLE,
    REFERENCE_CAPACITY_REACHED,
    UNKNOWN_REFERENCE,
    OWNER_CLOSED,
    OWNER_CONFLICT,
    REGISTRATION_CONFLICT,
    NAMESPACE_MISMATCH,
    ALIAS_COLLISION,
    KEY_MISSING,
    KEY_INVALIDATED,
    KEY_UNAVAILABLE,
    AUTHENTICATION_REQUIRED,
    KEYSTORE_UNAVAILABLE,
    CREATION_FAILED,
    POLICY_MISMATCH,
    HARDWARE_REQUIRED,
    PUBLIC_KEY_INVALID,
    KEY_CHANGED,
    KEY_REUSE,
    ATTESTATION_UNAVAILABLE,
    ATTESTATION_BOUNDS,
}

internal enum class RollbackState { NOT_NEEDED, COMPLETE, UNCERTAIN }

/** No exception, alias, DER or provider message is retained or formatted. */
internal sealed class KeyStoreOutcome<out T> {
    class Value<T>(val value: T) : KeyStoreOutcome<T>()
    class Failure(
        val error: DeviceKeyError,
        val rollback: RollbackState = RollbackState.NOT_NEEDED,
    ) : KeyStoreOutcome<Nothing>()

    final override fun toString(): String = when (this) {
        is Value -> "KeyStoreOutcome.Value([redacted])"
        is Failure -> "KeyStoreOutcome.Failure($error, $rollback)"
    }
}

/**
 * One in-process creation attempt. Rust's trusted pairing owner must generate
 * BOTH 32-byte values with its CSPRNG and ensure nonce freshness across attempts
 * and restarts. Byte validation cannot prove randomness or remote consent.
 * No alias/path/provider/algorithm string is accepted from a WebView.
 */
internal class KeyCreationRequest private constructor(
    private val handle: ByteArray,
    private val challenge: ByteArray,
) {
    private val consumed = AtomicBoolean(false)

    internal fun consumeForKeyOwner(): ConsumedKeyRequest? {
        if (!consumed.compareAndSet(false, true)) return null
        val request = ConsumedKeyRequest(handle.copyOf(), challenge.copyOf())
        handle.fill(0)
        challenge.fill(0)
        return request
    }

    override fun toString(): String = "KeyCreationRequest([redacted])"

    companion object {
        fun fromTrustedRust(handle: ByteArray, challenge: ByteArray): KeyStoreOutcome<KeyCreationRequest> {
            if (!DeviceKeyPolicy.validHandle(handle)) return KeyStoreOutcome.Failure(DeviceKeyError.INVALID_ENROLLMENT_HANDLE)
            if (!DeviceKeyPolicy.validChallenge(challenge)) return KeyStoreOutcome.Failure(DeviceKeyError.INVALID_ATTESTATION_CHALLENGE)
            return KeyStoreOutcome.Value(KeyCreationRequest(handle.copyOf(), challenge.copyOf()))
        }
    }
}

internal class ConsumedKeyRequest internal constructor(
    internal val handle: ByteArray,
    internal val challenge: ByteArray,
) {
    internal fun clear() { handle.fill(0); challenge.fill(0) }
    override fun toString(): String = "ConsumedKeyRequest([redacted])"
}

/**
 * Identity-scoped opaque reference. Constructing a lookalike does not register
 * it: the owner uses object identity in its private, bounded registry. There is
 * no alias or private-key accessor and no signing method.
 */
internal class DeviceKeyReference internal constructor(val role: DeviceKeyRole) {
    override fun toString(): String = "DeviceKeyReference($role, [redacted])"
}

/** Unverified public evidence only; remote chain/challenge/policy verification is still required. */
internal class UnverifiedKeyMaterial internal constructor(
    val role: DeviceKeyRole,
    val hardware: HardwareProtection,
    spki: ByteArray,
    certificates: List<ByteArray>,
) {
    private val publicSpki = spki.also {
        require(DeviceKeyPolicy.canonicalP256Spki(it)) { "Invalid bounded public key evidence" }
    }.copyOf()
    private val chain = certificates.also {
        require(DeviceKeyPolicy.attestationBounds(it.map { certificate -> certificate.size }) == null) { "Invalid bounded certificate evidence" }
    }.map { it.copyOf() }
    fun copyPublicSpki(): ByteArray = publicSpki.copyOf()
    fun copyAttestationChain(): List<ByteArray> = chain.map { it.copyOf() }
    override fun toString(): String = "UnverifiedKeyMaterial($role, [redacted])"
}

/** Created locally but NOT paired, enrolled, attestation-verified or authorized. */
internal class UncommittedDeviceKeySet internal constructor(
    internal val registration: KeySetRegistration,
    material: Map<DeviceKeyRole, UnverifiedKeyMaterial>,
) {
    private val material = material.toMap()
    fun reference(role: DeviceKeyRole): DeviceKeyReference = registration.reference(role)
    fun publicMaterial(role: DeviceKeyRole): UnverifiedKeyMaterial = material.getValue(role)
    override fun toString(): String = "UncommittedDeviceKeySet([redacted])"
}

/**
 * AndroidKeyStore creation, exact existing-key reopening and inspection only.
 *
 * Call off the main thread. No constructor/static initializer generates keys.
 * There is no Tauri command, Binder/receiver entry point, sign(bytes), exported
 * Signature/CryptoObject, authentication-success boolean, PIN or auth window.
 * Signing remains deliberately absent until a separate identity-matching,
 * one-shot BiometricPrompt CryptoObject coordinator is implemented and tested.
 *
 * The process-wide lock serializes this module. AndroidKeyStore has no atomic
 * create-if-absent API; this must be the sole writer for its fixed namespace
 * across the app UID's processes. Fresh unpredictable handles and collision
 * checks precede every generation. A crash is not a transaction rollback.
 * Paired-key persistence, recovery/revocation and remote attestation verification
 * are not implemented here. Reopening only observes existing keys named by the
 * trusted owner's already committed exact metadata; it never generates on error.
 * References are bounded, instance-owned and process-local. Explicit release is
 * memory-only, leaves all native aliases intact and cannot make bootstrap fresh.
 */
internal class DeviceKeyStore(context: Context) {
    private val appContext = context.applicationContext
    private val owner = KeyReferenceOwner()

    fun createKeySet(request: KeyCreationRequest): KeyStoreOutcome<UncommittedDeviceKeySet> {
        val input = request.consumeForKeyOwner()
            ?: return KeyStoreOutcome.Failure(DeviceKeyError.REQUEST_ALREADY_CONSUMED)
        return try {
            if (Looper.myLooper() == Looper.getMainLooper()) {
                KeyStoreOutcome.Failure(DeviceKeyError.WRONG_THREAD)
            } else {
                synchronized(OWNER_LOCK) { createLocked(input) }
            }
        } finally {
            input.clear()
        }
    }

    /** Policy/public evidence observation, not proof that a signing operation will succeed. */
    fun inspectPublicMaterial(reference: DeviceKeyReference): KeyStoreOutcome<UnverifiedKeyMaterial> {
        if (Looper.myLooper() == Looper.getMainLooper()) return KeyStoreOutcome.Failure(DeviceKeyError.WRONG_THREAD)
        return synchronized(OWNER_LOCK) {
            val inspection = InspectionAttempt()
            try {
                val registration = registryValue(REFERENCES.resolve(owner, reference))
                inspection.matched = registration
                requireDeviceSecure()
                val record = existingRecord(registration.descriptor, reference.role)
                val material = inspectKey(openStore(), record)
                requireDeviceSecure()
                KeyStoreOutcome.Value(material)
            } catch (failure: OwnerFailure) {
                inspection.matched?.let { REFERENCES.release(owner, it) }
                KeyStoreOutcome.Failure(failure.error)
            } catch (failure: Exception) {
                inspection.matched?.let { REFERENCES.release(owner, it) }
                KeyStoreOutcome.Failure(nativeError(failure, DeviceKeyError.KEY_UNAVAILABLE))
            }
        }
    }

    /**
     * No creation/import/authentication. Descriptor shape is NOT evidence of its
     * committed provenance or of enrollment; only the trusted native storage
     * owner may supply it. Preparing records and namespace scans are insufficient.
     * All three native policies/keys are re-inspected even on a cache hit.
     */
    fun reopenExistingKeySet(descriptor: ReopenKeySetDescriptor): KeyStoreOutcome<ReopenedDeviceKeySet> {
        if (Looper.myLooper() == Looper.getMainLooper()) return KeyStoreOutcome.Failure(DeviceKeyError.WRONG_THREAD)
        return synchronized(OWNER_LOCK) {
            val inspection = InspectionAttempt()
            try {
                val existing = registryValue(REFERENCES.findExact(owner, descriptor))
                // Assigned only after owner + complete tuple match. Conflicting
                // inputs must not invalidate another/rightful registration.
                inspection.matched = existing
                requireDeviceSecure()
                val store = openStore()
                val material = LinkedHashMap<DeviceKeyRole, UnverifiedKeyMaterial>()
                for (role in DeviceKeyRole.values()) {
                    material[role] = inspectKey(store, existingRecord(descriptor, role))
                }
                requireDeviceSecure()
                val registered = if (existing == null) {
                    registryValue(REFERENCES.publish(owner, descriptor, material))
                } else {
                    registryValue(REFERENCES.refresh(owner, existing, material))
                }
                KeyStoreOutcome.Value(registered.reopenedView())
            } catch (failure: OwnerFailure) {
                inspection.matched?.let { REFERENCES.release(owner, it) }
                KeyStoreOutcome.Failure(failure.error)
            } catch (failure: Exception) {
                inspection.matched?.let { REFERENCES.release(owner, it) }
                KeyStoreOutcome.Failure(nativeError(failure, DeviceKeyError.KEY_UNAVAILABLE))
            }
        }
    }

    /**
     * Read-only exact controller namespace observation before/after a trusted
     * startup batch. No incomplete, unknown or orphan controller alias is accepted.
     * This is not an enrollment mapper and never discovers replacement handles.
     */
    fun validateRecordedNamespace(handles: List<ByteArray>): KeyStoreOutcome<Unit> {
        if (Looper.myLooper() == Looper.getMainLooper()) return KeyStoreOutcome.Failure(DeviceKeyError.WRONG_THREAD)
        return synchronized(OWNER_LOCK) {
            var copied: List<ByteArray> = emptyList()
            try {
                registryValue(REFERENCES.requireOpen(owner))
                copied = registryValue(KeyNamespaceObservation.copyHandles(handles))
                val expected = LinkedHashSet<String>()
                for (handle in copied) for (role in DeviceKeyRole.values()) expected.add(aliasFor(handle, role))
                requireDeviceSecure()
                val observation = KeyNamespaceObservation(expected)
                val aliases = openStore().aliases()
                while (aliases.hasMoreElements()) {
                    // Check before fetching the next provider value. Native
                    // enumeration itself may allocate; no unbounded list copy.
                    observation.beforeNext()?.let { fail(it) }
                    observation.observe(aliases.nextElement())?.let { fail(it) }
                }
                observation.finish()?.let { fail(it) }
                requireDeviceSecure()
                KeyStoreOutcome.Value(Unit)
            } catch (failure: OwnerFailure) {
                KeyStoreOutcome.Failure(failure.error)
            } catch (failure: Exception) {
                KeyStoreOutcome.Failure(nativeError(failure, DeviceKeyError.KEYSTORE_UNAVAILABLE))
            } finally {
                copied.forEach { it.fill(0) }
            }
        }
    }

    /** Pure downward cleanup may run even when CE/screen-lock observations fail. */
    fun releaseReferences(set: ReopenedDeviceKeySet): KeyStoreOutcome<Unit> = synchronized(OWNER_LOCK) {
        REFERENCES.release(owner, set.registration)
    }

    /** Uncommitted creation uses the same lifetime accounting, not a second map. */
    fun releaseReferences(set: UncommittedDeviceKeySet): KeyStoreOutcome<Unit> = synchronized(OWNER_LOCK) {
        REFERENCES.release(owner, set.registration)
    }

    /** Closes only this instance's references permanently; never deletes native keys. */
    fun closeReferences(): KeyStoreOutcome<Unit> = synchronized(OWNER_LOCK) { REFERENCES.close(owner) }

    private fun existingRecord(descriptor: ReopenKeySetDescriptor, role: DeviceKeyRole): OwnedKey {
        val handle = descriptor.copyHandle()
        return try { OwnedKey(aliasFor(handle, role), role, descriptor.copySpki(role)) }
        finally { handle.fill(0) }
    }

    private fun <T> registryValue(result: KeyStoreOutcome<T>): T = when (result) {
        is KeyStoreOutcome.Value -> result.value
        is KeyStoreOutcome.Failure -> fail(result.error)
    }

    private fun createLocked(input: ConsumedKeyRequest): KeyStoreOutcome<UncommittedDeviceKeySet> {
        val created = ArrayList<OwnedKey>(DeviceKeyPolicy.KEYS_PER_SET)
        var store: KeyStore? = null
        // An in-flight generation must survive exception unwinding even when
        // no key identity was returned. Keep that operation state explicitly;
        // Kotlin 1.9's local-assignment analysis ignores the catch-only read.
        val generation = GenerationAttempt()
        return try {
            registryValue(REFERENCES.checkNewCreation(owner, input.handle))
            requireDeviceSecure()
            val currentStore = openStore()
            store = currentStore
            val aliases = DeviceKeyRole.values().associateWith { aliasFor(input.handle, it) }
            // No generator is created until every alias was observed absent.
            if (aliases.values.any { currentStore.containsAlias(it) }) fail(DeviceKeyError.ALIAS_COLLISION)
            val material = LinkedHashMap<DeviceKeyRole, UnverifiedKeyMaterial>()
            for (role in DeviceKeyRole.values()) {
                requireDeviceSecure()
                val alias = aliases.getValue(role)
                if (currentStore.containsAlias(alias)) fail(DeviceKeyError.ALIAS_COLLISION)
                val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                    // secp256r1 is prime256v1 (OID 1.2.840.10045.3.1.7).
                    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                    .setKeySize(256)
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setUserAuthenticationRequired(role == DeviceKeyRole.APPROVAL)
                    .setAttestationChallenge(input.challenge.copyOf())
                if (role == DeviceKeyRole.APPROVAL) {
                    spec.setUserAuthenticationParameters(
                        0,
                        KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL,
                    )
                }
                // No StrongBox preference/retry is used. Default provider output
                // must actually be >=TEE; software output is rejected/rolled back.
                val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, PROVIDER)
                generator.initialize(spec.build())
                generation.alias = alias
                val pair = generator.generateKeyPair()
                val publicSpki = publicSpki(pair.public)
                val record = OwnedKey(alias, role, publicSpki)
                created.add(record)
                generation.alias = null
                requireDeviceSecure()
                material[role] = inspectKey(currentStore, record)
                requireDeviceSecure()
            }
            if (!DeviceKeyPolicy.distinctPublicKeys(created.map { it.expectedSpki })) fail(DeviceKeyError.KEY_REUSE)
            requireDeviceSecure()
            // Shape helper only: using the descriptor for registration does not
            // claim that newly created keys have been durably committed/enrolled.
            val descriptor = registryValue(ReopenKeySetDescriptor.fromTrustedStorage(
                input.handle,
                material.getValue(DeviceKeyRole.APPROVAL).copyPublicSpki(),
                material.getValue(DeviceKeyRole.DENIAL).copyPublicSpki(),
                material.getValue(DeviceKeyRole.TRANSPORT).copyPublicSpki(),
            ))
            val registered = registryValue(REFERENCES.publish(owner, descriptor, material))
            KeyStoreOutcome.Value(UncommittedDeviceKeySet(registered, material))
        } catch (failure: OwnerFailure) {
            KeyStoreOutcome.Failure(failure.error, rollback(store, created, generation.alias))
        } catch (failure: Exception) {
            KeyStoreOutcome.Failure(nativeError(failure, DeviceKeyError.CREATION_FAILED), rollback(store, created, generation.alias))
        }
    }

    private fun inspectKey(store: KeyStore, record: OwnedKey): UnverifiedKeyMaterial {
        requireDeviceSecure()
        if (!store.containsAlias(record.alias)) fail(DeviceKeyError.KEY_MISSING)
        val privateKey = store.getKey(record.alias, null) as? PrivateKey ?: fail(DeviceKeyError.KEY_UNAVAILABLE)
        // This fixed-provider KeyInfo lookup only accepts native AndroidKeyStore
        // private keys. NEVER request ECPrivateKeySpec/PKCS8 or access encoded.
        val info = KeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_EC, PROVIDER)
            .getKeySpec(privateKey, KeyInfo::class.java)
        val hardware = hardwareProtection(info)
        val observed = KeyPolicyObservation(
            algorithmIsEc = privateKey.algorithm == KeyProperties.KEY_ALGORITHM_EC,
            sizeBits = info.keySize,
            originGenerated = info.origin == KeyProperties.ORIGIN_GENERATED,
            aliasMatches = info.keystoreAlias == record.alias,
            purposes = info.purposes,
            digests = info.digests.toList(),
            hardware = hardware,
            authenticationRequired = info.isUserAuthenticationRequired,
            authenticationValiditySeconds = info.userAuthenticationValidityDurationSeconds,
            authenticationTypes = info.userAuthenticationType,
            hardwareAuthenticationEnforced = info.isUserAuthenticationRequirementEnforcedBySecureHardware,
            onBodyExtension = info.isUserAuthenticationValidWhileOnBody,
            trustedPresenceRequired = info.isTrustedUserPresenceRequired,
            confirmationRequired = info.isUserConfirmationRequired,
            hasKeyValidityWindow = info.keyValidityStart != null ||
                info.keyValidityForOriginationEnd != null || info.keyValidityForConsumptionEnd != null,
        )
        DeviceKeyPolicy.validate(record.role, observed)?.let { fail(it) }
        val certificates = store.getCertificateChain(record.alias) ?: fail(DeviceKeyError.ATTESTATION_UNAVAILABLE)
        if (certificates.isEmpty() || certificates.size > DeviceKeyPolicy.MAX_CERTIFICATES) fail(DeviceKeyError.ATTESTATION_BOUNDS)
        val leaf = certificates.first() as? X509Certificate ?: fail(DeviceKeyError.ATTESTATION_UNAVAILABLE)
        val spki = publicSpki(leaf.publicKey)
        if (!spki.contentEquals(record.expectedSpki)) fail(DeviceKeyError.KEY_CHANGED)
        val chain = ArrayList<ByteArray>(certificates.size)
        var total = 0
        for (certificate in certificates) {
            if (certificate !is X509Certificate) fail(DeviceKeyError.ATTESTATION_UNAVAILABLE)
            val encoded = certificate.encoded
            if (encoded.isEmpty() || encoded.size > DeviceKeyPolicy.MAX_CERTIFICATE_BYTES) fail(DeviceKeyError.ATTESTATION_BOUNDS)
            total += encoded.size
            if (total > DeviceKeyPolicy.MAX_CERTIFICATE_CHAIN_BYTES) fail(DeviceKeyError.ATTESTATION_BOUNDS)
            chain.add(encoded)
        }
        DeviceKeyPolicy.attestationBounds(chain.map { it.size })?.let { fail(it) }
        requireDeviceSecure()
        return UnverifiedKeyMaterial(record.role, hardware, spki, chain)
    }

    private fun requireDeviceSecure() {
        requireCredentialStorage()
        val state = try {
            DeviceKeyPolicy.lockState(appContext.getSystemService(KeyguardManager::class.java)?.isDeviceSecure)
        } catch (_: Exception) { DeviceLockState.UNAVAILABLE }
        when (state) {
            DeviceLockState.CONFIGURED -> Unit
            DeviceLockState.MISSING -> fail(DeviceKeyError.LOCK_MISSING)
            DeviceLockState.UNAVAILABLE -> fail(DeviceKeyError.LOCK_UNAVAILABLE)
        }
    }

    private fun requireCredentialStorage() {
        val available = try {
            if (appContext.isDeviceProtectedStorage) fail(DeviceKeyError.CREDENTIAL_STORAGE_UNAVAILABLE)
            appContext.getSystemService(UserManager::class.java)?.isUserUnlocked
        } catch (failure: OwnerFailure) { throw failure }
        catch (_: Exception) { fail(DeviceKeyError.CREDENTIAL_STORAGE_UNAVAILABLE) }
        when (available) {
            true -> Unit
            false -> fail(DeviceKeyError.CREDENTIAL_STORAGE_LOCKED)
            null -> fail(DeviceKeyError.CREDENTIAL_STORAGE_UNAVAILABLE)
        }
    }

    private fun openStore(): KeyStore = try {
        KeyStore.getInstance(PROVIDER).apply { load(null) }
    } catch (_: Exception) { fail(DeviceKeyError.KEYSTORE_UNAVAILABLE) }

    @Suppress("DEPRECATION") // API30 has only the legacy hardware boolean; securityLevel is API31+.
    private fun hardwareProtection(info: KeyInfo): HardwareProtection = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
        when (info.securityLevel) {
            KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> HardwareProtection.TEE
            KeyProperties.SECURITY_LEVEL_STRONGBOX -> HardwareProtection.STRONGBOX
            KeyProperties.SECURITY_LEVEL_SOFTWARE -> HardwareProtection.SOFTWARE
            else -> HardwareProtection.UNAVAILABLE
        }
    } else {
        if (info.isInsideSecureHardware) HardwareProtection.LEGACY_SECURE_HARDWARE else HardwareProtection.SOFTWARE
    }

    private fun publicSpki(key: PublicKey): ByteArray {
        if (key.algorithm != KeyProperties.KEY_ALGORITHM_EC || key.format != "X.509") fail(DeviceKeyError.PUBLIC_KEY_INVALID)
        val encoded = key.encoded ?: fail(DeviceKeyError.PUBLIC_KEY_INVALID)
        if (!DeviceKeyPolicy.canonicalP256Spki(encoded)) fail(DeviceKeyError.PUBLIC_KEY_INVALID)
        return encoded
    }

    private fun rollback(store: KeyStore?, created: List<OwnedKey>, uncertainAlias: String?): RollbackState {
        if (created.isEmpty() && uncertainAlias == null) return RollbackState.NOT_NEEDED
        if (store == null) return RollbackState.UNCERTAIN
        var uncertain = false
        // A generation failure without returned/publicly identified key material
        // does NOT authorize deleting whatever later appeared under that alias.
        if (uncertainAlias != null) {
            try { if (store.containsAlias(uncertainAlias)) uncertain = true }
            catch (_: Exception) { uncertain = true }
        }
        for (record in created.asReversed()) {
            try {
                val exists = store.containsAlias(record.alias)
                val current = if (exists) store.getCertificate(record.alias)?.publicKey?.encoded else null
                when (DeviceKeyPolicy.rollbackDecision(record.expectedSpki, current, exists)) {
                    RollbackDecision.NOTHING_TO_DELETE -> Unit
                    RollbackDecision.LEAVE_UNCERTAIN -> uncertain = true
                    RollbackDecision.DELETE_MATCHING_CREATED_KEY -> {
                        store.deleteEntry(record.alias)
                        if (store.containsAlias(record.alias)) uncertain = true
                    }
                }
            } catch (_: Exception) { uncertain = true }
        }
        return if (uncertain) RollbackState.UNCERTAIN else RollbackState.COMPLETE
    }

    private companion object {
        const val PROVIDER = "AndroidKeyStore"
        val OWNER_LOCK = Any()
        val REFERENCES = KeyReferenceRegistry()

        fun aliasFor(handle: ByteArray, role: DeviceKeyRole): String {
            if (!DeviceKeyPolicy.validHandle(handle)) fail(DeviceKeyError.INVALID_ENROLLMENT_HANDLE)
            val hex = handle.joinToString("") { byte -> (byte.toInt() and 0xff).toString(16).padStart(2, '0') }
            val suffix = when (role) {
                DeviceKeyRole.APPROVAL -> "approval"
                DeviceKeyRole.DENIAL -> "denial"
                DeviceKeyRole.TRANSPORT -> "transport"
            }
            return "${DeviceKeyPolicy.ALIAS_NAMESPACE}$hex.$suffix".also {
                if (it.length > DeviceKeyPolicy.MAX_ALIAS_CHARACTERS) fail(DeviceKeyError.INVALID_ENROLLMENT_HANDLE)
            }
        }

        fun fail(error: DeviceKeyError): Nothing = throw OwnerFailure(error)

        fun nativeError(error: Exception, fallback: DeviceKeyError): DeviceKeyError {
            var current: Throwable? = error
            var result = fallback
            repeat(4) {
                when (current) {
                    is KeyPermanentlyInvalidatedException -> return DeviceKeyError.KEY_INVALIDATED
                    is UserNotAuthenticatedException -> result = DeviceKeyError.AUTHENTICATION_REQUIRED
                    is UnrecoverableKeyException -> if (result == fallback) result = DeviceKeyError.KEY_UNAVAILABLE
                }
                current = current?.cause
            }
            return result
        }
    }
}

private class OwnedKey(val alias: String, val role: DeviceKeyRole, spki: ByteArray) {
    val expectedSpki = spki.copyOf()
    override fun toString(): String = "OwnedKey([redacted])"
}

private class GenerationAttempt {
    var alias: String? = null
    override fun toString(): String = "GenerationAttempt([redacted])"
}

/** Explicit catch-path obligation; Kotlin1.9 does not track catch-only local assignments. */
private class InspectionAttempt {
    var matched: KeySetRegistration? = null
    override fun toString(): String = "InspectionAttempt([redacted])"
}

private class OwnerFailure(val error: DeviceKeyError) : RuntimeException(null, null, false, false)

/** Synthetic observations in unit tests are NOT AndroidKeyStore/device proof. */
internal data class KeyPolicyObservation(
    val algorithmIsEc: Boolean,
    val sizeBits: Int,
    val originGenerated: Boolean,
    val aliasMatches: Boolean,
    val purposes: Int,
    val digests: List<String>,
    val hardware: HardwareProtection,
    val authenticationRequired: Boolean,
    val authenticationValiditySeconds: Int,
    val authenticationTypes: Int,
    val hardwareAuthenticationEnforced: Boolean,
    val onBodyExtension: Boolean,
    val trustedPresenceRequired: Boolean,
    val confirmationRequired: Boolean,
    val hasKeyValidityWindow: Boolean,
) {
    override fun toString(): String = "KeyPolicyObservation([redacted])"
}

internal enum class RollbackDecision { NOTHING_TO_DELETE, DELETE_MATCHING_CREATED_KEY, LEAVE_UNCERTAIN }

internal object DeviceKeyPolicy {
    const val ALIAS_NAMESPACE = "dev.dkk115.uacremote.keystore.v1."
    const val HANDLE_BYTES = 32
    const val CHALLENGE_BYTES = 32
    const val PUBLIC_SPKI_BYTES = 91
    const val KEYS_PER_SET = 3
    const val MAX_REFERENCES = 32 * KEYS_PER_SET
    const val MAX_ALIAS_CHARACTERS = 128
    const val MAX_CERTIFICATES = 8
    const val MAX_CERTIFICATE_BYTES = 8 * 1024
    const val MAX_CERTIFICATE_CHAIN_BYTES = 32 * 1024

    // Public curve constants only. No key generation occurs at initialization.
    private val field = BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16)
    private val coefficientB = BigInteger("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16)
    private val spkiPrefix = intArrayOf(0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04).map { it.toByte() }.toByteArray()

    fun validHandle(value: ByteArray): Boolean = value.size == HANDLE_BYTES && value.any { it != 0.toByte() }
    fun validChallenge(value: ByteArray): Boolean = value.size == CHALLENGE_BYTES && value.any { it != 0.toByte() }
    fun lockState(value: Boolean?): DeviceLockState = when (value) {
        true -> DeviceLockState.CONFIGURED
        false -> DeviceLockState.MISSING
        null -> DeviceLockState.UNAVAILABLE
    }

    fun validate(role: DeviceKeyRole, observed: KeyPolicyObservation): DeviceKeyError? {
        if (observed.hardware !in setOf(HardwareProtection.TEE, HardwareProtection.STRONGBOX, HardwareProtection.LEGACY_SECURE_HARDWARE)) return DeviceKeyError.HARDWARE_REQUIRED
        if (!observed.algorithmIsEc || observed.sizeBits != 256 || !observed.originGenerated || !observed.aliasMatches ||
            observed.purposes != KeyProperties.PURPOSE_SIGN || observed.digests != listOf(KeyProperties.DIGEST_SHA256) ||
            observed.onBodyExtension || observed.trustedPresenceRequired || observed.confirmationRequired || observed.hasKeyValidityWindow
        ) return DeviceKeyError.POLICY_MISMATCH
        if (role == DeviceKeyRole.APPROVAL) {
            // Public KeyInfo documentation calls per-use -1; Android11/12 AOSP
            // extraction also reports 0 for absent AUTH_TIMEOUT. Neither is a
            // positive auth window. Remote attestation must verify its absence.
            if (!observed.authenticationRequired || observed.authenticationValiditySeconds !in setOf(-1, 0) ||
                observed.authenticationTypes != (KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL) ||
                !observed.hardwareAuthenticationEnforced
            ) return DeviceKeyError.POLICY_MISMATCH
        } else if (observed.authenticationRequired || observed.authenticationTypes != 0 || observed.hardwareAuthenticationEnforced ||
            observed.authenticationValiditySeconds !in setOf(-1, 0)
        ) return DeviceKeyError.POLICY_MISMATCH
        return null
    }

    fun canonicalP256Spki(bytes: ByteArray): Boolean {
        if (bytes.size != PUBLIC_SPKI_BYTES || spkiPrefix.indices.any { bytes[it] != spkiPrefix[it] }) return false
        val x = BigInteger(1, bytes.copyOfRange(27, 59))
        val y = BigInteger(1, bytes.copyOfRange(59, 91))
        if (x >= field || y >= field) return false
        val right = x.modPow(BigInteger.valueOf(3), field).subtract(x.multiply(BigInteger.valueOf(3))).add(coefficientB).mod(field)
        return y.multiply(y).mod(field) == right
    }

    fun distinctPublicKeys(keys: List<ByteArray>): Boolean = keys.size == KEYS_PER_SET &&
        keys.indices.all { left -> (left + 1 until keys.size).all { right -> !keys[left].contentEquals(keys[right]) } }

    fun attestationBounds(sizes: List<Int>): DeviceKeyError? = if (sizes.isEmpty() || sizes.size > MAX_CERTIFICATES ||
        sizes.any { it <= 0 || it > MAX_CERTIFICATE_BYTES } || sizes.sum() > MAX_CERTIFICATE_CHAIN_BYTES
    ) DeviceKeyError.ATTESTATION_BOUNDS else null

    fun rollbackDecision(createdSpki: ByteArray?, currentSpki: ByteArray?, aliasExists: Boolean): RollbackDecision = when {
        !aliasExists -> RollbackDecision.NOTHING_TO_DELETE
        createdSpki == null || currentSpki == null -> RollbackDecision.LEAVE_UNCERTAIN
        !canonicalP256Spki(createdSpki) || !canonicalP256Spki(currentSpki) -> RollbackDecision.LEAVE_UNCERTAIN
        createdSpki.contentEquals(currentSpki) -> RollbackDecision.DELETE_MATCHING_CREATED_KEY
        else -> RollbackDecision.LEAVE_UNCERTAIN
    }
}
