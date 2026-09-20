// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.security

import java.math.BigInteger
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

/** Pure synthetic public metadata. No Context, key generation, AndroidKeyStore or auth objects. */
class KeyReferenceRegistryTest {
    private fun <T> value(result: KeyStoreOutcome<T>): T = when (result) {
        is KeyStoreOutcome.Value -> result.value
        is KeyStoreOutcome.Failure -> throw AssertionError("Synthetic metadata failed: ${result.error}")
    }
    private fun failure(expected: DeviceKeyError, result: KeyStoreOutcome<*>) {
        assertTrue(result is KeyStoreOutcome.Failure)
        assertEquals(expected, (result as KeyStoreOutcome.Failure).error)
    }
    private fun descriptor(handle: Int = 1, firstPoint: Int = 1): ReopenKeySetDescriptor = value(
        ReopenKeySetDescriptor.fromTrustedStorage(ByteArray(32) { handle.toByte() },
            publicPoint(firstPoint), publicPoint(firstPoint + 1), publicPoint(firstPoint + 2)),
    )
    private fun material(descriptor: ReopenKeySetDescriptor, marker: Byte = 1): Map<DeviceKeyRole, UnverifiedKeyMaterial> =
        DeviceKeyRole.values().associateWith { role ->
            // Bounded synthetic certificate-shaped bytes, NOT X.509/attestation.
            UnverifiedKeyMaterial(role, HardwareProtection.TEE, descriptor.copySpki(role), listOf(byteArrayOf(marker)))
        }

    @Test fun descriptorCopiesAndValidatesExactNamedKeysWithoutClaimingCommitOrAttestation() {
        val handle = ByteArray(32) { 7 }
        val first = publicPoint(1)
        val second = publicPoint(2)
        val third = publicPoint(3)
        val observed = value(ReopenKeySetDescriptor.fromTrustedStorage(handle, first, second, third))
        handle.fill(0); first.fill(0); second.fill(0); third.fill(0)
        assertArrayEquals(ByteArray(32) { 7 }, observed.copyHandle())
        assertArrayEquals(publicPoint(1), observed.copySpki(DeviceKeyRole.APPROVAL))
        val returned = observed.copySpki(DeviceKeyRole.DENIAL); returned.fill(0)
        assertArrayEquals(publicPoint(2), observed.copySpki(DeviceKeyRole.DENIAL))
        assertEquals("ReopenKeySetDescriptor([redacted])", observed.toString())
        for (badHandle in listOf(ByteArray(0), ByteArray(31) { 1 }, ByteArray(33) { 1 }, ByteArray(32))) {
            failure(DeviceKeyError.INVALID_ENROLLMENT_HANDLE,
                ReopenKeySetDescriptor.fromTrustedStorage(badHandle, publicPoint(1), publicPoint(2), publicPoint(3)))
        }
        for (bad in listOf(ByteArray(0), ByteArray(90), ByteArray(91), publicPoint(1) + byteArrayOf(0))) {
            failure(DeviceKeyError.PUBLIC_KEY_INVALID,
                ReopenKeySetDescriptor.fromTrustedStorage(ByteArray(32) { 1 }, bad, publicPoint(2), publicPoint(3)))
        }
        failure(DeviceKeyError.KEY_REUSE, ReopenKeySetDescriptor.fromTrustedStorage(
            ByteArray(32) { 1 }, publicPoint(1), publicPoint(1), publicPoint(3)))
    }

    @Test fun repeatedLookupAndReinspectionRefreshReuseOneCanonicalRegistrationAtCapacity() {
        val registry = KeyReferenceRegistry(1)
        val owner = KeyReferenceOwner()
        val descriptor = descriptor()
        val registered = value(registry.publish(owner, descriptor, material(descriptor)))
        val view = registered.reopenedView()
        repeat(20) {
            val existing = value(registry.findExact(owner, descriptor))!!
            assertSame(registered, existing)
            val refreshed = value(registry.refresh(owner, existing, material(descriptor, 2)))
            assertSame(view, refreshed.reopenedView())
            for (role in DeviceKeyRole.values()) assertSame(view.reference(role), refreshed.reference(role))
        }
        assertEquals(1, registry.registrationCount())
        assertEquals(3, registry.referenceCount())
        assertArrayEquals(byteArrayOf(2), view.publicMaterial(DeviceKeyRole.APPROVAL).copyAttestationChain().single())
        failure(DeviceKeyError.REFERENCE_CAPACITY_REACHED, registry.findExact(owner, descriptor(2, 4)))
        failure(DeviceKeyError.REFERENCE_CAPACITY_REACHED, registry.checkNewCreation(owner, ByteArray(32) { 2 }))
        assertEquals(3, registry.referenceCount())
    }

    @Test fun crossOwnerLookupReleaseAndHandleConflictNeverStealOrEvictReferences() {
        val registry = KeyReferenceRegistry()
        val firstOwner = KeyReferenceOwner()
        val otherOwner = KeyReferenceOwner()
        val descriptor = descriptor()
        val registered = value(registry.publish(firstOwner, descriptor, material(descriptor)))
        failure(DeviceKeyError.OWNER_CONFLICT, registry.findExact(otherOwner, descriptor))
        failure(DeviceKeyError.OWNER_CONFLICT, registry.resolve(otherOwner, registered.reference(DeviceKeyRole.APPROVAL)))
        failure(DeviceKeyError.OWNER_CONFLICT, registry.release(otherOwner, registered))
        failure(DeviceKeyError.OWNER_CONFLICT, registry.checkNewCreation(otherOwner, descriptor.copyHandle()))
        failure(DeviceKeyError.ALIAS_COLLISION, registry.checkNewCreation(firstOwner, descriptor.copyHandle()))
        failure(DeviceKeyError.REGISTRATION_CONFLICT, registry.findExact(firstOwner, descriptor(1, 4)))
        assertSame(registered, value(registry.resolve(firstOwner, registered.reference(DeviceKeyRole.DENIAL))))
        assertFalse(registered.released)
        assertEquals(3, registry.referenceCount())
    }

    @Test fun rolePermutationAndPublicKeyReuseUnderAnotherHandleAreRejected() {
        val registry = KeyReferenceRegistry()
        val owner = KeyReferenceOwner()
        val descriptor = descriptor()
        val registered = value(registry.publish(owner, descriptor, material(descriptor)))
        val permuted = value(ReopenKeySetDescriptor.fromTrustedStorage(descriptor.copyHandle(),
            descriptor.copySpki(DeviceKeyRole.DENIAL), descriptor.copySpki(DeviceKeyRole.APPROVAL), descriptor.copySpki(DeviceKeyRole.TRANSPORT)))
        failure(DeviceKeyError.REGISTRATION_CONFLICT, registry.findExact(owner, permuted))
        failure(DeviceKeyError.KEY_REUSE, registry.findExact(owner, descriptor(2, 1)))
        val oneReused = value(ReopenKeySetDescriptor.fromTrustedStorage(ByteArray(32) { 3 }, publicPoint(4), publicPoint(5), publicPoint(1)))
        failure(DeviceKeyError.KEY_REUSE, registry.findExact(KeyReferenceOwner(), oneReused))
        assertSame(registered, value(registry.findExact(owner, descriptor)))
    }

    @Test fun partialOrMismatchedObservationPublishesNoReferences() {
        val registry = KeyReferenceRegistry()
        val owner = KeyReferenceOwner()
        val descriptor = descriptor()
        val complete = material(descriptor)
        val missing = complete - DeviceKeyRole.TRANSPORT
        failure(DeviceKeyError.POLICY_MISMATCH, registry.publish(owner, descriptor, missing))
        val swapped = complete.toMutableMap().apply { this[DeviceKeyRole.APPROVAL] = complete.getValue(DeviceKeyRole.DENIAL) }
        failure(DeviceKeyError.POLICY_MISMATCH, registry.publish(owner, descriptor, swapped))
        val wrongKey = complete.toMutableMap().apply {
            this[DeviceKeyRole.APPROVAL] = UnverifiedKeyMaterial(DeviceKeyRole.APPROVAL, HardwareProtection.TEE, publicPoint(4), listOf(byteArrayOf(1)))
        }
        failure(DeviceKeyError.POLICY_MISMATCH, registry.publish(owner, descriptor, wrongKey))
        val software = complete.toMutableMap().apply {
            this[DeviceKeyRole.TRANSPORT] = UnverifiedKeyMaterial(DeviceKeyRole.TRANSPORT, HardwareProtection.SOFTWARE,
                descriptor.copySpki(DeviceKeyRole.TRANSPORT), listOf(byteArrayOf(1)))
        }
        failure(DeviceKeyError.POLICY_MISMATCH, registry.publish(owner, descriptor, software))
        assertEquals(0, registry.registrationCount())
        assertEquals(0, registry.referenceCount())
        assertNull(value(registry.findExact(owner, descriptor)))
    }

    @Test fun failedExactReinspectionCleanupInvalidatesOnlyItsOwnWholeSet() {
        val registry = KeyReferenceRegistry()
        val owner = KeyReferenceOwner()
        val otherOwner = KeyReferenceOwner()
        val one = descriptor()
        val two = descriptor(2, 4)
        val failed = value(registry.publish(owner, one, material(one)))
        val retained = value(registry.publish(otherOwner, two, material(two)))
        // This models only the cleanup action used after a real native failure;
        // it does not fabricate or exercise an Android inspection result.
        value(registry.release(owner, failed))
        for (role in DeviceKeyRole.values()) {
            failure(DeviceKeyError.UNKNOWN_REFERENCE, registry.resolve(owner, failed.reference(role)))
            assertSame(retained, value(registry.resolve(otherOwner, retained.reference(role))))
        }
        assertEquals(1, registry.registrationCount())
        assertEquals(3, registry.referenceCount())
    }

    @Test fun staleReleaseIsIdempotentAndCannotRemoveANewerRegistrationForTheSameHandle() {
        val registry = KeyReferenceRegistry(1)
        val owner = KeyReferenceOwner()
        val descriptor = descriptor()
        val old = value(registry.publish(owner, descriptor, material(descriptor)))
        value(registry.release(owner, old))
        val current = value(registry.publish(owner, descriptor, material(descriptor)))
        assertNotSame(old, current)
        assertNotSame(old.reopenedView(), current.reopenedView())
        value(registry.release(owner, old))
        for (role in DeviceKeyRole.values()) {
            assertNotSame(old.reference(role), current.reference(role))
            failure(DeviceKeyError.UNKNOWN_REFERENCE, registry.resolve(owner, old.reference(role)))
            assertSame(current, value(registry.resolve(owner, current.reference(role))))
        }
        assertEquals(3, registry.referenceCount())
    }

    @Test fun createdUncommittedAndReopenedViewsShareOneRegistrationWithoutPromotingTrust() {
        val registry = KeyReferenceRegistry()
        val owner = KeyReferenceOwner()
        val descriptor = descriptor()
        value(registry.checkNewCreation(owner, descriptor.copyHandle()))
        val registration = value(registry.publish(owner, descriptor, material(descriptor)))
        val created = UncommittedDeviceKeySet(registration, material(descriptor))
        val cached = value(registry.findExact(owner, descriptor))!!
        val reopened = value(registry.refresh(owner, cached, material(descriptor))).reopenedView()
        for (role in DeviceKeyRole.values()) assertSame(created.reference(role), reopened.reference(role))
        assertEquals("UncommittedDeviceKeySet([redacted])", created.toString())
        assertEquals("ReopenedDeviceKeySet([redacted])", reopened.toString())
        value(registry.release(owner, created.registration))
        value(registry.release(owner, reopened.registration))
        assertEquals(0, registry.referenceCount())
    }

    @Test fun closeIsPermanentIdempotentAndFreesOnlyTheClosingOwnersCapacity() {
        val registry = KeyReferenceRegistry(2)
        val owner = KeyReferenceOwner()
        val otherOwner = KeyReferenceOwner()
        val one = descriptor()
        val two = descriptor(2, 4)
        val old = value(registry.publish(owner, one, material(one)))
        val retained = value(registry.publish(otherOwner, two, material(two)))
        value(registry.close(owner))
        value(registry.close(owner))
        value(registry.release(owner, old))
        failure(DeviceKeyError.OWNER_CLOSED, registry.findExact(owner, one))
        failure(DeviceKeyError.OWNER_CLOSED, registry.checkNewCreation(owner, ByteArray(32) { 3 }))
        failure(DeviceKeyError.OWNER_CLOSED, registry.publish(owner, one, material(one)))
        failure(DeviceKeyError.OWNER_CLOSED, registry.resolve(owner, old.reference(DeviceKeyRole.APPROVAL)))
        assertSame(retained, value(registry.findExact(otherOwner, two)))
        assertEquals(3, registry.referenceCount())
        val replacementOwner = KeyReferenceOwner()
        val replacement = value(registry.publish(replacementOwner, one, material(one)))
        assertNotSame(old.reference(DeviceKeyRole.APPROVAL), replacement.reference(DeviceKeyRole.APPROVAL))
        assertEquals(6, registry.referenceCount())
    }

    @Test fun lookalikeReferencesAndForeignRegistrySetsHaveNoMembership() {
        val registry = KeyReferenceRegistry()
        val owner = KeyReferenceOwner()
        val descriptor = descriptor()
        val registered = value(registry.publish(owner, descriptor, material(descriptor)))
        failure(DeviceKeyError.UNKNOWN_REFERENCE, registry.resolve(owner, DeviceKeyReference(DeviceKeyRole.APPROVAL)))
        val foreign = value(KeyReferenceRegistry().publish(owner, descriptor, material(descriptor)))
        failure(DeviceKeyError.UNKNOWN_REFERENCE, registry.release(owner, foreign))
        failure(DeviceKeyError.UNKNOWN_REFERENCE, registry.refresh(owner, foreign, material(descriptor)))
        assertSame(registered, value(registry.resolve(owner, registered.reference(DeviceKeyRole.APPROVAL))))
        assertEquals("KeyReferenceRegistry([redacted])", registry.toString())
        assertEquals("KeyReferenceOwner([redacted])", owner.toString())
        assertEquals("KeySetRegistration([redacted])", registered.toString())
        assertEquals(96, DeviceKeyPolicy.MAX_REFERENCES)
    }

    @Test(expected = IllegalArgumentException::class)
    fun capacityCannotExceedTheProductionReferenceBound() { KeyReferenceRegistry(33) }

    @Test fun recordedNamespaceHandlesAreBoundedUniqueCopiedAndAllowAnEmptyExpectation() {
        assertTrue(value(KeyNamespaceObservation.copyHandles(emptyList())).isEmpty())
        val original = ByteArray(32) { 1 }
        val copied = value(KeyNamespaceObservation.copyHandles(listOf(original)))
        original.fill(0)
        assertArrayEquals(ByteArray(32) { 1 }, copied.single())
        assertEquals(32, value(KeyNamespaceObservation.copyHandles(List(32) { index -> ByteArray(32) { (index + 1).toByte() } })).size)
        for (invalid in listOf(listOf(ByteArray(32)), listOf(ByteArray(31) { 1 }),
            listOf(ByteArray(32) { 1 }, ByteArray(32) { 1 }),
            List(33) { index -> ByteArray(32) { (index + 1).toByte() } })) {
            failure(DeviceKeyError.NAMESPACE_MISMATCH, KeyNamespaceObservation.copyHandles(invalid))
        }
    }

    @Test fun namespaceRequiresEveryExactControllerAliasAndRejectsOrphansPartialNamesAndDuplicates() {
        val expected = expectedAliases()
        val exact = KeyNamespaceObservation(expected)
        assertNull(exact.observe("another.application.key"))
        for (alias in expected.reversed()) assertNull(exact.observe(alias))
        assertNull(exact.finish())
        assertEquals("KeyNamespaceObservation([redacted])", exact.toString())
        val missing = KeyNamespaceObservation(expected)
        expected.drop(1).forEach { assertNull(missing.observe(it)) }
        assertEquals(DeviceKeyError.NAMESPACE_MISMATCH, missing.finish())
        // Failure is latched: a late additional alias cannot rehabilitate this scan.
        assertEquals(DeviceKeyError.NAMESPACE_MISMATCH, missing.observe(expected.first()))
        for (unexpected in listOf(DeviceKeyPolicy.ALIAS_NAMESPACE,
            DeviceKeyPolicy.ALIAS_NAMESPACE + "partial",
            DeviceKeyPolicy.ALIAS_NAMESPACE + "02".repeat(32) + ".approval",
            DeviceKeyPolicy.ALIAS_NAMESPACE + "01".repeat(32) + ".unexpected")) {
            val orphan = KeyNamespaceObservation(expected)
            expected.forEach { assertNull(orphan.observe(it)) }
            assertEquals(DeviceKeyError.NAMESPACE_MISMATCH, orphan.observe(unexpected))
            assertEquals(DeviceKeyError.NAMESPACE_MISMATCH, orphan.finish())
        }
        val duplicated = KeyNamespaceObservation(expected)
        assertNull(duplicated.observe(expected.first()))
        assertEquals(DeviceKeyError.NAMESPACE_MISMATCH, duplicated.observe(expected.first()))
    }

    @Test fun namespaceScanBoundsCountIgnoredNamesAndNeverAcceptExtraControllerKeysForEmptyMetadata() {
        assertEquals(4096, KeyNamespaceObservation.MAX_ALIASES)
        assertEquals(2048, KeyNamespaceObservation.MAX_OBSERVED_ALIAS_CHARACTERS)
        assertEquals("dev.dkk115.uacremote.keystore.v1.", DeviceKeyPolicy.ALIAS_NAMESPACE)
        val full = KeyNamespaceObservation(emptySet())
        repeat(KeyNamespaceObservation.MAX_ALIASES) { assertNull(full.beforeNext()); assertNull(full.observe("other.$it")) }
        assertNull(full.finish())
        assertEquals(DeviceKeyError.KEYSTORE_UNAVAILABLE, full.beforeNext())
        assertEquals(DeviceKeyError.KEYSTORE_UNAVAILABLE, full.observe("one-more-foreign-name"))
        val longName = KeyNamespaceObservation(emptySet())
        assertEquals(DeviceKeyError.KEYSTORE_UNAVAILABLE, longName.observe("x".repeat(2049)))
        val noMetadata = KeyNamespaceObservation(emptySet())
        assertEquals(DeviceKeyError.NAMESPACE_MISMATCH, noMetadata.observe(expectedAliases().first()))
    }

    private fun expectedAliases(): Set<String> = setOf("approval", "denial", "transport").map { suffix ->
        DeviceKeyPolicy.ALIAS_NAMESPACE + "01".repeat(32) + "." + suffix
    }.toSet()

    // Public P-256 generator-point arithmetic makes distinct synthetic public
    // fixtures without private-key material, randomness or a native provider.
    private fun publicPoint(index: Int): ByteArray {
        require(index in 1..6)
        val p = BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16)
        val gx = BigInteger("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16)
        val gy = BigInteger("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16)
        var x = gx
        var y = gy
        repeat(index - 1) {
            val slope = if (x == gx && y == gy) {
                x.multiply(x).multiply(BigInteger.valueOf(3)).subtract(BigInteger.valueOf(3)).mod(p)
                    .multiply(y.multiply(BigInteger.valueOf(2)).mod(p).modInverse(p)).mod(p)
            } else {
                gy.subtract(y).mod(p).multiply(gx.subtract(x).mod(p).modInverse(p)).mod(p)
            }
            val nextX = slope.multiply(slope).subtract(x).subtract(gx).mod(p)
            y = slope.multiply(x.subtract(nextX)).subtract(y).mod(p)
            x = nextX
        }
        val prefix = "3059301306072a8648ce3d020106082a8648ce3d03010703420004"
        return (prefix + x.toString(16).padStart(64, '0') + y.toString(16).padStart(64, '0'))
            .chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    }
}
