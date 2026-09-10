// SPDX-License-Identifier: GPL-2.0-or-later

package dev.dkk115.uacremote.security

import android.security.keystore.KeyProperties
import java.math.BigInteger
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Synthetic metadata/public curve fixtures only. Never instantiates AndroidKeyStore. */
class DeviceKeyStorePolicyTest {
    private fun observation(role: DeviceKeyRole): KeyPolicyObservation = KeyPolicyObservation(
        algorithmIsEc = true,
        sizeBits = 256,
        originGenerated = true,
        aliasMatches = true,
        purposes = KeyProperties.PURPOSE_SIGN,
        digests = listOf(KeyProperties.DIGEST_SHA256),
        hardware = HardwareProtection.TEE,
        authenticationRequired = role == DeviceKeyRole.APPROVAL,
        authenticationValiditySeconds = 0,
        authenticationTypes = if (role == DeviceKeyRole.APPROVAL) {
            KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL
        } else 0,
        hardwareAuthenticationEnforced = role == DeviceKeyRole.APPROVAL,
        onBodyExtension = false,
        trustedPresenceRequired = false,
        confirmationRequired = false,
        hasKeyValidityWindow = false,
    )

    // Public P-256 generator point, not a generated/stored private key.
    private fun publicFixture(): ByteArray = hex(
        "3059301306072a8648ce3d020106082a8648ce3d03010703420004" +
            "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296" +
            "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
    )

    private fun differentPublicFixture(): ByteArray {
        val result = publicFixture()
        val field = BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16)
        val y = BigInteger(1, result.copyOfRange(59, 91))
        val inverse = field.subtract(y).toString(16).padStart(64, '0')
        hex(inverse).copyInto(result, 59)
        return result
    }

    private fun hex(value: String): ByteArray = value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    @Test fun approvalRequiresHardwarePerUseAndBothNativeAuthenticatorTypes() {
        val approval = observation(DeviceKeyRole.APPROVAL)
        for (perUseSentinel in listOf(-1, 0)) {
            assertNull(DeviceKeyPolicy.validate(DeviceKeyRole.APPROVAL, approval.copy(authenticationValiditySeconds = perUseSentinel)))
        }
        for (timeout in listOf(-2, 1, 30, Int.MAX_VALUE)) {
            assertEquals(DeviceKeyError.POLICY_MISMATCH, DeviceKeyPolicy.validate(DeviceKeyRole.APPROVAL, approval.copy(authenticationValiditySeconds = timeout)))
        }
        for (types in listOf(0, KeyProperties.AUTH_BIOMETRIC_STRONG, KeyProperties.AUTH_DEVICE_CREDENTIAL, -1)) {
            assertEquals(DeviceKeyError.POLICY_MISMATCH, DeviceKeyPolicy.validate(DeviceKeyRole.APPROVAL, approval.copy(authenticationTypes = types)))
        }
        assertEquals(DeviceKeyError.POLICY_MISMATCH, DeviceKeyPolicy.validate(DeviceKeyRole.APPROVAL, approval.copy(authenticationRequired = false)))
        assertEquals(DeviceKeyError.POLICY_MISMATCH, DeviceKeyPolicy.validate(DeviceKeyRole.APPROVAL, approval.copy(hardwareAuthenticationEnforced = false)))
    }

    @Test fun denialAndTransportNeverAcquireAnAuthenticationRequirement() {
        for (role in listOf(DeviceKeyRole.DENIAL, DeviceKeyRole.TRANSPORT)) {
            val native = observation(role)
            assertNull(DeviceKeyPolicy.validate(role, native))
            assertEquals(DeviceKeyError.POLICY_MISMATCH, DeviceKeyPolicy.validate(role, native.copy(authenticationRequired = true)))
            assertEquals(DeviceKeyError.POLICY_MISMATCH, DeviceKeyPolicy.validate(role, native.copy(authenticationTypes = KeyProperties.AUTH_DEVICE_CREDENTIAL)))
            assertEquals(DeviceKeyError.POLICY_MISMATCH, DeviceKeyPolicy.validate(role, native.copy(authenticationValiditySeconds = 30)))
            assertEquals(DeviceKeyError.POLICY_MISMATCH, DeviceKeyPolicy.validate(role, native.copy(hardwareAuthenticationEnforced = true)))
        }
    }

    @Test fun softwareAndUnknownSecurityLevelsAreNotHardwareFallbacks() {
        for (role in DeviceKeyRole.values()) {
            for (hardware in listOf(HardwareProtection.TEE, HardwareProtection.STRONGBOX, HardwareProtection.LEGACY_SECURE_HARDWARE)) {
                assertNull(DeviceKeyPolicy.validate(role, observation(role).copy(hardware = hardware)))
            }
            for (hardware in listOf(HardwareProtection.SOFTWARE, HardwareProtection.UNAVAILABLE)) {
                assertEquals(DeviceKeyError.HARDWARE_REQUIRED, DeviceKeyPolicy.validate(role, observation(role).copy(hardware = hardware)))
            }
        }
    }

    @Test fun algorithmOriginDigestPurposeAndExtraValidityPoliciesFailClosed() {
        val baseline = observation(DeviceKeyRole.APPROVAL)
        val changes = listOf(
            baseline.copy(algorithmIsEc = false), baseline.copy(sizeBits = 384),
            baseline.copy(originGenerated = false), baseline.copy(aliasMatches = false),
            baseline.copy(purposes = KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY),
            baseline.copy(digests = listOf(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)),
            baseline.copy(digests = emptyList()), baseline.copy(onBodyExtension = true),
            baseline.copy(trustedPresenceRequired = true), baseline.copy(confirmationRequired = true),
            baseline.copy(hasKeyValidityWindow = true),
        )
        for (changed in changes) assertEquals(DeviceKeyError.POLICY_MISMATCH, DeviceKeyPolicy.validate(DeviceKeyRole.APPROVAL, changed))
    }

    @Test fun deviceSecureObservationIsDistinctFromMissingAndUnavailable() {
        assertEquals(DeviceLockState.CONFIGURED, DeviceKeyPolicy.lockState(true))
        assertEquals(DeviceLockState.MISSING, DeviceKeyPolicy.lockState(false))
        assertEquals(DeviceLockState.UNAVAILABLE, DeviceKeyPolicy.lockState(null))
    }

    @Test fun trustedRequestInputsAreBoundedCopiedAndConsumedOnce() {
        val handle = ByteArray(32) { 0x31 }
        val challenge = ByteArray(32) { 0x42 }
        var observations = 0
        val result = KeyCreationRequest.fromTrustedRust(handle, challenge) { observations += 1 }
        assertTrue(result is KeyStoreOutcome.Value)
        val request = when (result) {
            is KeyStoreOutcome.Value -> result.value
            is KeyStoreOutcome.Failure -> throw AssertionError("Synthetic request metadata was rejected")
        }
        handle.fill(0)
        challenge.fill(0)
        val consumed = request.consumeForKeyOwner()!!
        consumed.checkCurrent()
        assertEquals(1, observations)
        assertTrue(consumed.handle.all { it == 0x31.toByte() })
        assertTrue(consumed.challenge.all { it == 0x42.toByte() })
        assertNull(request.consumeForKeyOwner())
        assertEquals("KeyCreationRequest([redacted])", request.toString())
        consumed.clear()
        assertTrue(consumed.handle.all { it == 0.toByte() })
        assertTrue(consumed.challenge.all { it == 0.toByte() })
        for (length in listOf(0, 31, 33, 4096)) {
            assertFalse(DeviceKeyPolicy.validHandle(ByteArray(length) { 1 }))
            assertFalse(DeviceKeyPolicy.validChallenge(ByteArray(length) { 1 }))
        }
        assertFalse(DeviceKeyPolicy.validHandle(ByteArray(32)))
        assertFalse(DeviceKeyPolicy.validChallenge(ByteArray(32)))
    }

    @Test fun canonicalPublicSpkiAndRoleKeySeparationAreStrict() {
        val first = publicFixture()
        val second = differentPublicFixture()
        assertTrue(DeviceKeyPolicy.canonicalP256Spki(first))
        assertTrue(DeviceKeyPolicy.canonicalP256Spki(second))
        assertFalse(DeviceKeyPolicy.canonicalP256Spki(first + byteArrayOf(0)))
        assertFalse(DeviceKeyPolicy.canonicalP256Spki(first.copyOf().also { it[22] = 0 }))
        assertFalse(DeviceKeyPolicy.canonicalP256Spki(first.copyOf().also { it.fill(0, 27, 91) }))
        assertFalse(DeviceKeyPolicy.distinctPublicKeys(listOf(first, second, first.copyOf())))
        assertFalse(DeviceKeyPolicy.distinctPublicKeys(listOf(first, second)))
    }

    @Test fun originalFreshnessObservationSurvivesConsumptionAndCannotRearmAfterFailure() {
        var observations = 0
        var current = true
        val result = KeyCreationRequest.fromTrustedRust(ByteArray(32) { 1 }, ByteArray(32) { 2 }) {
            observations += 1
            check(current) { "Synthetic original observation expired" }
        }
        val request = when (result) {
            is KeyStoreOutcome.Value -> result.value
            is KeyStoreOutcome.Failure -> throw AssertionError("Synthetic shape rejected")
        }
        val consumed = request.consumeForKeyOwner()!!
        consumed.checkCurrent() // Model the observation AFTER owner/provider preflight.
        consumed.checkCurrent() // Model first generation admission; no Android call.
        assertEquals(2, observations)
        current = false
        fun mustReject() {
            var failed = false
            try { consumed.checkCurrent() } catch (_: RuntimeException) { failed = true }
            assertTrue(failed)
        }
        mustReject() // A later role cannot use the old successful observation.
        assertEquals(3, observations)
        current = true
        mustReject() // A failed attempt cannot be rearmed by a later callback.
        assertEquals(3, observations)
        consumed.clear()
        mustReject()
        assertEquals(3, observations)
        assertNull(request.consumeForKeyOwner())
    }

    @Test fun attestationOutputsHaveCountPerCertificateAndTotalBounds() {
        assertNull(DeviceKeyPolicy.attestationBounds(listOf(1024, 2048, 1024)))
        assertNull(DeviceKeyPolicy.attestationBounds(List(4) { 8192 }))
        for (sizes in listOf(emptyList(), listOf(0), listOf(8193), List(9) { 1 }, List(5) { 8192 }, listOf(-1))) {
            assertEquals(DeviceKeyError.ATTESTATION_BOUNDS, DeviceKeyPolicy.attestationBounds(sizes))
        }
    }

    @Test fun rollbackNeverDeletesUnidentifiedOrReplacedKeys() {
        val owned = publicFixture()
        val replacement = differentPublicFixture()
        assertEquals(RollbackDecision.NOTHING_TO_DELETE, DeviceKeyPolicy.rollbackDecision(owned, null, false))
        assertEquals(RollbackDecision.DELETE_MATCHING_CREATED_KEY, DeviceKeyPolicy.rollbackDecision(owned, owned.copyOf(), true))
        assertEquals(RollbackDecision.LEAVE_UNCERTAIN, DeviceKeyPolicy.rollbackDecision(null, owned, true))
        assertEquals(RollbackDecision.LEAVE_UNCERTAIN, DeviceKeyPolicy.rollbackDecision(owned, null, true))
        assertEquals(RollbackDecision.LEAVE_UNCERTAIN, DeviceKeyPolicy.rollbackDecision(owned, replacement, true))
        assertEquals(RollbackDecision.LEAVE_UNCERTAIN, DeviceKeyPolicy.rollbackDecision(owned, ByteArray(91), true))
    }

    @Test fun publicEvidenceAndReferencesDoNotLeakOrShareMutableByteArrays() {
        val spki = publicFixture()
        val certificate = byteArrayOf(1, 2, 3) // Synthetic byte metadata, not an X.509/device certificate.
        val material = UnverifiedKeyMaterial(DeviceKeyRole.APPROVAL, HardwareProtection.TEE, spki, listOf(certificate))
        spki.fill(0)
        certificate.fill(0)
        assertArrayEquals(publicFixture(), material.copyPublicSpki())
        assertArrayEquals(byteArrayOf(1, 2, 3), material.copyAttestationChain().single())
        val returned = material.copyPublicSpki()
        returned.fill(0)
        assertArrayEquals(publicFixture(), material.copyPublicSpki())
        val one = DeviceKeyReference(DeviceKeyRole.APPROVAL)
        val two = DeviceKeyReference(DeviceKeyRole.APPROVAL)
        assertNotSame(one, two)
        assertEquals("DeviceKeyReference(APPROVAL, [redacted])", one.toString())
        assertEquals("UnverifiedKeyMaterial(APPROVAL, [redacted])", material.toString())
        assertEquals("KeyStoreOutcome.Value([redacted])", KeyStoreOutcome.Value(material).toString())
        assertEquals("KeyPolicyObservation([redacted])", observation(DeviceKeyRole.APPROVAL).toString())
    }
}
