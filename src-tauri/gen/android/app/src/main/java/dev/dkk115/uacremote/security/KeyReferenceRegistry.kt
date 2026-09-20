// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.security

import java.util.IdentityHashMap

/**
 * Bounded copied shape from the trusted native owner's committed local metadata.
 * Constructing this value proves neither commit provenance, randomness, enrollment
 * nor attestation. Preparing/partial records must never be turned into this call.
 * There is no caller-selected alias, provider, role map or signing input.
 */
internal class ReopenKeySetDescriptor private constructor(
    private val handle: ByteArray,
    private val approval: ByteArray,
    private val denial: ByteArray,
    private val transport: ByteArray,
) {
    internal fun copyHandle(): ByteArray = handle.copyOf()
    internal fun copySpki(role: DeviceKeyRole): ByteArray = spki(role).copyOf()
    internal fun sameKeys(other: ReopenKeySetDescriptor): Boolean =
        DeviceKeyRole.values().all { spki(it).contentEquals(other.spki(it)) }
    internal fun sharesKey(other: ReopenKeySetDescriptor): Boolean = DeviceKeyRole.values().any { left ->
        DeviceKeyRole.values().any { right -> spki(left).contentEquals(other.spki(right)) }
    }
    internal fun matches(material: Map<DeviceKeyRole, UnverifiedKeyMaterial>): Boolean =
        material.size == DeviceKeyPolicy.KEYS_PER_SET && DeviceKeyRole.values().all { role ->
            val value = material[role]
            value != null && value.role == role && value.copyPublicSpki().contentEquals(spki(role)) &&
                value.hardware in setOf(HardwareProtection.TEE, HardwareProtection.STRONGBOX, HardwareProtection.LEGACY_SECURE_HARDWARE)
        }
    private fun spki(role: DeviceKeyRole): ByteArray = when (role) {
        DeviceKeyRole.APPROVAL -> approval
        DeviceKeyRole.DENIAL -> denial
        DeviceKeyRole.TRANSPORT -> transport
    }
    override fun toString(): String = "ReopenKeySetDescriptor([redacted])"

    companion object {
        fun fromTrustedStorage(
            handle: ByteArray,
            approvalSpki: ByteArray,
            denialSpki: ByteArray,
            transportSpki: ByteArray,
        ): KeyStoreOutcome<ReopenKeySetDescriptor> {
            // Copy first: later caller mutations cannot change validation/cache
            // identity. All copies are bounded before allocation.
            if (!DeviceKeyPolicy.validHandle(handle)) return KeyStoreOutcome.Failure(DeviceKeyError.INVALID_ENROLLMENT_HANDLE)
            if (listOf(approvalSpki, denialSpki, transportSpki).any { it.size != DeviceKeyPolicy.PUBLIC_SPKI_BYTES }) {
                return KeyStoreOutcome.Failure(DeviceKeyError.PUBLIC_KEY_INVALID)
            }
            val savedHandle = handle.copyOf()
            val keys = listOf(approvalSpki.copyOf(), denialSpki.copyOf(), transportSpki.copyOf())
            if (!DeviceKeyPolicy.validHandle(savedHandle)) return KeyStoreOutcome.Failure(DeviceKeyError.INVALID_ENROLLMENT_HANDLE)
            if (keys.any { !DeviceKeyPolicy.canonicalP256Spki(it) }) return KeyStoreOutcome.Failure(DeviceKeyError.PUBLIC_KEY_INVALID)
            if (!DeviceKeyPolicy.distinctPublicKeys(keys)) return KeyStoreOutcome.Failure(DeviceKeyError.KEY_REUSE)
            return KeyStoreOutcome.Value(ReopenKeySetDescriptor(savedHandle, keys[0], keys[1], keys[2]))
        }
    }
}

/** Identity belongs to exactly one native DeviceKeyStore instance, never a UI id. */
internal class KeyReferenceOwner {
    @Volatile internal var closed: Boolean = false
        private set
    internal fun close() { closed = true }
    override fun toString(): String = "KeyReferenceOwner([redacted])"
}

/** One canonical registration, not one independent lease for each lookup. */
internal class KeySetRegistration internal constructor(
    internal val owner: KeyReferenceOwner,
    internal val registryIdentity: Any,
    internal val descriptor: ReopenKeySetDescriptor,
    material: Map<DeviceKeyRole, UnverifiedKeyMaterial>,
) {
    private val references = DeviceKeyRole.values().associateWith { DeviceKeyReference(it) }
    @Volatile private var observation = material.toMap()
    @Volatile internal var released = false
        private set
    private val reopened = ReopenedDeviceKeySet(this)

    fun reference(role: DeviceKeyRole): DeviceKeyReference = references.getValue(role)
    fun publicMaterial(role: DeviceKeyRole): UnverifiedKeyMaterial = observation.getValue(role)
    internal fun reopenedView(): ReopenedDeviceKeySet = reopened
    internal fun refresh(material: Map<DeviceKeyRole, UnverifiedKeyMaterial>) { observation = material.toMap() }
    internal fun release() { released = true }
    override fun toString(): String = "KeySetRegistration([redacted])"
}

/** Last unverified public observation; references still require a fresh owner lookup. */
internal class ReopenedDeviceKeySet internal constructor(internal val registration: KeySetRegistration) {
    fun reference(role: DeviceKeyRole): DeviceKeyReference = registration.reference(role)
    fun publicMaterial(role: DeviceKeyRole): UnverifiedKeyMaterial = registration.publicMaterial(role)
    override fun toString(): String = "ReopenedDeviceKeySet([redacted])"
}

/**
 * Pure process-local bookkeeping. Never opens Android objects or accepts native
 * success booleans. DeviceKeyStore holds its namespace lock across native
 * inspection and publication; these synchronized methods also protect the maps.
 * A released set held by a stale caller is not retained by any registry map.
 */
internal class KeyReferenceRegistry(private val maximumSets: Int = DeviceKeyPolicy.MAX_REFERENCES / DeviceKeyPolicy.KEYS_PER_SET) {
    private val identity = Any()
    private val sets = LinkedHashMap<CreationHandle, KeySetRegistration>()
    private val references = IdentityHashMap<DeviceKeyReference, KeySetRegistration>()

    init { require(maximumSets in 1..(DeviceKeyPolicy.MAX_REFERENCES / DeviceKeyPolicy.KEYS_PER_SET)) { "Invalid bounded reference capacity" } }

    @Synchronized fun requireOpen(owner: KeyReferenceOwner): KeyStoreOutcome<Unit> =
        if (owner.closed) failure(DeviceKeyError.OWNER_CLOSED) else KeyStoreOutcome.Value(Unit)

    /** Check only; native caller still holds the namespace lock until publication. */
    @Synchronized fun checkNewCreation(owner: KeyReferenceOwner, handle: ByteArray): KeyStoreOutcome<Unit> {
        if (owner.closed) return failure(DeviceKeyError.OWNER_CLOSED)
        if (!DeviceKeyPolicy.validHandle(handle)) return failure(DeviceKeyError.INVALID_ENROLLMENT_HANDLE)
        val existing = sets[CreationHandle(handle)]
        if (existing != null) return failure(if (existing.owner !== owner) DeviceKeyError.OWNER_CONFLICT else DeviceKeyError.ALIAS_COLLISION)
        if (sets.size >= maximumSets) return failure(DeviceKeyError.REFERENCE_CAPACITY_REACHED)
        return KeyStoreOutcome.Value(Unit)
    }

    @Synchronized fun findExact(owner: KeyReferenceOwner, descriptor: ReopenKeySetDescriptor): KeyStoreOutcome<KeySetRegistration?> {
        if (owner.closed) return failure(DeviceKeyError.OWNER_CLOSED)
        val existing = sets[CreationHandle(descriptor.copyHandle())]
        if (existing != null) {
            if (existing.owner !== owner) return failure(DeviceKeyError.OWNER_CONFLICT)
            if (!existing.descriptor.sameKeys(descriptor)) return failure(DeviceKeyError.REGISTRATION_CONFLICT)
            return KeyStoreOutcome.Value(existing)
        }
        if (sets.values.any { it.descriptor.sharesKey(descriptor) }) return failure(DeviceKeyError.KEY_REUSE)
        if (sets.size >= maximumSets) return failure(DeviceKeyError.REFERENCE_CAPACITY_REACHED)
        return KeyStoreOutcome.Value(null)
    }

    /** Validate everything before any reference becomes visible. No callbacks. */
    @Synchronized fun publish(
        owner: KeyReferenceOwner,
        descriptor: ReopenKeySetDescriptor,
        material: Map<DeviceKeyRole, UnverifiedKeyMaterial>,
    ): KeyStoreOutcome<KeySetRegistration> {
        when (val candidate = findExact(owner, descriptor)) {
            is KeyStoreOutcome.Failure -> return candidate
            is KeyStoreOutcome.Value -> if (candidate.value != null) return failure(DeviceKeyError.REGISTRATION_CONFLICT)
        }
        if (!descriptor.matches(material)) return failure(DeviceKeyError.POLICY_MISMATCH)
        val registration = KeySetRegistration(owner, identity, descriptor, material)
        val handle = CreationHandle(descriptor.copyHandle())
        sets[handle] = registration
        for (role in DeviceKeyRole.values()) references[registration.reference(role)] = registration
        return KeyStoreOutcome.Value(registration)
    }

    @Synchronized fun refresh(
        owner: KeyReferenceOwner,
        registration: KeySetRegistration,
        material: Map<DeviceKeyRole, UnverifiedKeyMaterial>,
    ): KeyStoreOutcome<KeySetRegistration> {
        val error = registeredError(owner, registration)
        if (error != null) return failure(error)
        if (!registration.descriptor.matches(material)) return failure(DeviceKeyError.POLICY_MISMATCH)
        registration.refresh(material)
        return KeyStoreOutcome.Value(registration)
    }

    @Synchronized fun resolve(owner: KeyReferenceOwner, reference: DeviceKeyReference): KeyStoreOutcome<KeySetRegistration> {
        if (owner.closed) return failure(DeviceKeyError.OWNER_CLOSED)
        val registration = references[reference] ?: return failure(DeviceKeyError.UNKNOWN_REFERENCE)
        val error = registeredError(owner, registration)
        if (error != null) return failure(error)
        if (registration.reference(reference.role) !== reference) return failure(DeviceKeyError.UNKNOWN_REFERENCE)
        return KeyStoreOutcome.Value(registration)
    }

    /** Downward-only and idempotent, including after this owner's close. */
    @Synchronized fun release(owner: KeyReferenceOwner, registration: KeySetRegistration): KeyStoreOutcome<Unit> {
        if (registration.registryIdentity !== identity) return failure(DeviceKeyError.UNKNOWN_REFERENCE)
        if (registration.owner !== owner) return failure(DeviceKeyError.OWNER_CONFLICT)
        if (registration.released) return KeyStoreOutcome.Value(Unit)
        val handle = CreationHandle(registration.descriptor.copyHandle())
        if (sets[handle] !== registration) return failure(DeviceKeyError.UNKNOWN_REFERENCE)
        for (role in DeviceKeyRole.values()) references.remove(registration.reference(role))
        sets.remove(handle)
        registration.release()
        return KeyStoreOutcome.Value(Unit)
    }

    @Synchronized fun close(owner: KeyReferenceOwner): KeyStoreOutcome<Unit> {
        // Close admission first. Even an unexpected bookkeeping failure must
        // never leave this instance eligible to create/reopen native operations.
        owner.close()
        // At most32 records; copy avoids mutating the iteration. No native key is
        // touched and no other owner's entries are invalidated.
        val owned = sets.values.filter { it.owner === owner }
        for (registration in owned) {
            when (val result = release(owner, registration)) {
                is KeyStoreOutcome.Failure -> return result
                is KeyStoreOutcome.Value -> Unit
            }
        }
        return KeyStoreOutcome.Value(Unit)
    }

    @Synchronized fun registrationCount(): Int = sets.size
    @Synchronized fun referenceCount(): Int = references.size
    private fun registeredError(owner: KeyReferenceOwner, registration: KeySetRegistration): DeviceKeyError? = when {
        owner.closed -> DeviceKeyError.OWNER_CLOSED
        registration.registryIdentity !== identity -> DeviceKeyError.UNKNOWN_REFERENCE
        registration.owner !== owner -> DeviceKeyError.OWNER_CONFLICT
        registration.released || sets[CreationHandle(registration.descriptor.copyHandle())] !== registration -> DeviceKeyError.UNKNOWN_REFERENCE
        else -> null
    }
    private fun failure(error: DeviceKeyError): KeyStoreOutcome.Failure = KeyStoreOutcome.Failure(error)
    override fun toString(): String = "KeyReferenceRegistry([redacted])"

    private class CreationHandle(handle: ByteArray) {
        private val bytes = handle.copyOf()
        override fun equals(other: Any?): Boolean = other is CreationHandle && bytes.contentEquals(other.bytes)
        override fun hashCode(): Int = bytes.contentHashCode()
        override fun toString(): String = "CreationHandle([redacted])"
    }
}

/** Pure bounded enumeration policy; strings are never emitted or used as new identities. */
internal class KeyNamespaceObservation(expected: Set<String>) {
    private val expected = expected.also { entries ->
        require(entries.size <= DeviceKeyPolicy.MAX_REFERENCES && entries.all {
            it.startsWith(DeviceKeyPolicy.ALIAS_NAMESPACE) && it.length <= DeviceKeyPolicy.MAX_ALIAS_CHARACTERS
        }) { "Invalid bounded namespace expectation" }
    }.toSet()
    private val observed = HashSet<String>()
    private var examined = 0
    private var failed: DeviceKeyError? = null

    fun beforeNext(): DeviceKeyError? {
        if (failed != null) return failed
        if (examined >= MAX_ALIASES) failed = DeviceKeyError.KEYSTORE_UNAVAILABLE
        return failed
    }
    fun observe(alias: String): DeviceKeyError? {
        beforeNext()?.let { return it }
        examined += 1
        if (alias.length > MAX_OBSERVED_ALIAS_CHARACTERS) {
            failed = DeviceKeyError.KEYSTORE_UNAVAILABLE
        } else if (alias.startsWith(DeviceKeyPolicy.ALIAS_NAMESPACE) &&
            (alias !in expected || !observed.add(alias))) {
            failed = DeviceKeyError.NAMESPACE_MISMATCH
        }
        return failed
    }
    fun finish(): DeviceKeyError? {
        if (failed == null && observed != expected) failed = DeviceKeyError.NAMESPACE_MISMATCH
        return failed
    }
    override fun toString(): String = "KeyNamespaceObservation([redacted])"

    companion object {
        // Same bounds as the existing bootstrap LegacyPolicyObservation. They
        // include ignored non-controller aliases; no early successful break.
        const val MAX_ALIASES = 4096
        const val MAX_OBSERVED_ALIAS_CHARACTERS = 2048

        fun copyHandles(handles: List<ByteArray>): KeyStoreOutcome<List<ByteArray>> {
            val maximum = DeviceKeyPolicy.MAX_REFERENCES / DeviceKeyPolicy.KEYS_PER_SET
            if (handles.size > maximum) return KeyStoreOutcome.Failure(DeviceKeyError.NAMESPACE_MISMATCH)
            val copied = ArrayList<ByteArray>(handles.size)
            for (handle in handles) {
                if (copied.size == maximum || handle.size != DeviceKeyPolicy.HANDLE_BYTES) {
                    copied.forEach { it.fill(0) }
                    return KeyStoreOutcome.Failure(DeviceKeyError.NAMESPACE_MISMATCH)
                }
                val saved = handle.copyOf()
                if (!DeviceKeyPolicy.validHandle(saved) || copied.any { it.contentEquals(saved) }) {
                    saved.fill(0)
                    copied.forEach { it.fill(0) }
                    return KeyStoreOutcome.Failure(DeviceKeyError.NAMESPACE_MISMATCH)
                }
                copied.add(saved)
            }
            return KeyStoreOutcome.Value(copied)
        }
    }
}
