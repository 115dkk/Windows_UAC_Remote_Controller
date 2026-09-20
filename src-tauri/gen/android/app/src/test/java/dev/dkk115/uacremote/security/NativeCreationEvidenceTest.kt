// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.security

import dev.dkk115.uacremote.nativecore.NativeKeyCreationInput
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/** Pure public-evidence conversion with synthetic SOFTWARE-generated points and
 * opaque non-X.509 bytes. Never opens AndroidKeyStore or proves hardware policy. */
class NativeCreationEvidenceTest {
    private fun publicPoint(): ByteArray = KeyPairGenerator.getInstance("EC").run {
        initialize(ECGenParameterSpec("secp256r1")); generateKeyPair().public.encoded
    }
    private fun <T> value(result: KeyStoreOutcome<T>): T = when (result) {
        is KeyStoreOutcome.Value -> result.value
        is KeyStoreOutcome.Failure -> throw AssertionError("Synthetic evidence shape rejected")
    }
    private fun input() = NativeKeyCreationInput(ByteArray(32) { 1 }, ByteArray(32) { 2 }, ByteArray(32) { 3 })
    private fun descriptor() = value(ReopenKeySetDescriptor.fromTrustedStorage(ByteArray(32) { 1 }, publicPoint(), publicPoint(), publicPoint()))
    private fun material(descriptor: ReopenKeySetDescriptor): Map<DeviceKeyRole, UnverifiedKeyMaterial> =
        DeviceKeyRole.values().associateWith { role ->
            UnverifiedKeyMaterial(role, HardwareProtection.TEE, descriptor.copySpki(role), listOf(byteArrayOf((role.ordinal + 1).toByte())))
        }
    private fun rejects(action: () -> Unit) {
        try { action(); fail("Invalid synthetic shape was accepted") } catch (_: IllegalArgumentException) { }
    }

    @Test fun outputCopiesOnlyBoundedPublicEvidenceWithoutAnotherReferenceOwner() {
        val descriptor = descriptor()
        val material = material(descriptor)
        val registry = KeyReferenceRegistry(1)
        val owner = KeyReferenceOwner()
        value(registry.publish(owner, descriptor, material))
        val input = input()
        val exported = NativeCreationEvidence.copyObserved(input, descriptor, material)
        input.handle.fill(0); input.challenge.fill(0); input.ceremonyNonce.fill(0)
        assertArrayEquals(ByteArray(32) { 1 }, exported.handle)
        assertArrayEquals(ByteArray(32) { 2 }, exported.challenge)
        assertArrayEquals(ByteArray(32) { 3 }, exported.ceremonyNonce)
        assertArrayEquals(descriptor.copySpki(DeviceKeyRole.APPROVAL), exported.approval.spki)
        assertArrayEquals(descriptor.copySpki(DeviceKeyRole.DENIAL), exported.denial.spki)
        assertArrayEquals(descriptor.copySpki(DeviceKeyRole.TRANSPORT), exported.transport.spki)
        exported.approval.spki.fill(0)
        exported.denial.certificates.single().fill(0)
        assertArrayEquals(descriptor.copySpki(DeviceKeyRole.APPROVAL), material.getValue(DeviceKeyRole.APPROVAL).copyPublicSpki())
        assertArrayEquals(byteArrayOf(2), material.getValue(DeviceKeyRole.DENIAL).copyAttestationChain().single())
        assertEquals(1, registry.registrationCount())
        assertEquals(3, registry.referenceCount())
    }

    @Test fun originalInputWidthsAndNonzeroValuesAreCheckedBeforeConversion() {
        assertTrue(NativeCreationEvidence.validInput(input()))
        for (bad in listOf(ByteArray(0), ByteArray(31) { 1 }, ByteArray(33) { 1 }, ByteArray(32))) {
            assertFalse(NativeCreationEvidence.validInput(NativeKeyCreationInput(bad, ByteArray(32) { 2 }, ByteArray(32) { 3 })))
            assertFalse(NativeCreationEvidence.validInput(NativeKeyCreationInput(ByteArray(32) { 1 }, bad, ByteArray(32) { 3 })))
            assertFalse(NativeCreationEvidence.validInput(NativeKeyCreationInput(ByteArray(32) { 1 }, ByteArray(32) { 2 }, bad)))
        }
    }

    @Test fun missingSwappedAndMismatchedRoleMaterialCannotCrossTheCallback() {
        val descriptor = descriptor()
        val material = material(descriptor)
        rejects { NativeCreationEvidence.copyObserved(input(), descriptor, material - DeviceKeyRole.TRANSPORT) }
        val swapped = material.toMutableMap()
        swapped[DeviceKeyRole.APPROVAL] = material.getValue(DeviceKeyRole.DENIAL)
        swapped[DeviceKeyRole.DENIAL] = material.getValue(DeviceKeyRole.APPROVAL)
        rejects { NativeCreationEvidence.copyObserved(input(), descriptor, swapped) }
        val wrongTuple = material.toMutableMap()
        wrongTuple[DeviceKeyRole.APPROVAL] = UnverifiedKeyMaterial(DeviceKeyRole.APPROVAL, HardwareProtection.TEE, publicPoint(), listOf(byteArrayOf(1)))
        rejects { NativeCreationEvidence.copyObserved(input(), descriptor, wrongTuple) }
        val wrongHandle = NativeKeyCreationInput(ByteArray(32) { 9 }, ByteArray(32) { 2 }, ByteArray(32) { 3 })
        rejects { NativeCreationEvidence.copyObserved(wrongHandle, descriptor, material) }
    }

    @Test fun evidenceBoundsAreEnforcedBeforeNativeRetentionAndAbiCopies() {
        val key = publicPoint()
        for (chain in listOf(emptyList(), List(9) { byteArrayOf(1) }, listOf(ByteArray(8193)), List(5) { ByteArray(8192) }, listOf(ByteArray(0)))) {
            rejects { UnverifiedKeyMaterial(DeviceKeyRole.APPROVAL, HardwareProtection.TEE, key, chain) }
        }
        val maximum = UnverifiedKeyMaterial(DeviceKeyRole.APPROVAL, HardwareProtection.TEE, key, List(4) { ByteArray(8192) })
        assertEquals(32768, maximum.copyAttestationChain().sumOf { it.size })
    }
}
