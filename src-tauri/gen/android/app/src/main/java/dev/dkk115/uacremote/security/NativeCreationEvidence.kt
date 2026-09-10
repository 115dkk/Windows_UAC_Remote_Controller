// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.security

import dev.dkk115.uacremote.nativecore.NativeCreatedKeyEvidence
import dev.dkk115.uacremote.nativecore.NativeCreatedRoleEvidence
import dev.dkk115.uacremote.nativecore.NativeKeyCreationInput

/** Public-evidence shape only. PC attestation remains the sole remote adjudicator.
 * No key/reference wrapper is stored in or returned through these ABI records. */
internal object NativeCreationEvidence {
    fun validInput(input: NativeKeyCreationInput): Boolean =
        DeviceKeyPolicy.validHandle(input.handle) && DeviceKeyPolicy.validChallenge(input.challenge) &&
            DeviceKeyPolicy.validChallenge(input.ceremonyNonce)

    fun copyObserved(
        input: NativeKeyCreationInput,
        descriptor: ReopenKeySetDescriptor,
        material: Map<DeviceKeyRole, UnverifiedKeyMaterial>,
    ): NativeCreatedKeyEvidence {
        require(validInput(input)) { "Invalid bounded creation input" }
        require(descriptor.copyHandle().contentEquals(input.handle) && descriptor.matches(material)) {
            "Creation observation differs from its original public tuple"
        }
        fun role(expected: DeviceKeyRole): NativeCreatedRoleEvidence {
            val observed = material.getValue(expected)
            require(observed.role == expected) { "Creation role mismatch" }
            // UnverifiedKeyMaterial already enforced each bound BEFORE retaining
            // native certificate bytes. Repeat before generated-ABI conversion.
            val spki = observed.copyPublicSpki()
            val certificates = observed.copyAttestationChain()
            require(DeviceKeyPolicy.canonicalP256Spki(spki) &&
                DeviceKeyPolicy.attestationBounds(certificates.map { it.size }) == null) {
                "Invalid bounded creation evidence"
            }
            return NativeCreatedRoleEvidence(spki, certificates)
        }
        return NativeCreatedKeyEvidence(
            input.handle.copyOf(), input.challenge.copyOf(), input.ceremonyNonce.copyOf(),
            role(DeviceKeyRole.APPROVAL), role(DeviceKeyRole.DENIAL), role(DeviceKeyRole.TRANSPORT),
        )
    }
}
