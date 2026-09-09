// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.security

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Synthetic framing/object identities only; no Android key/Signature/ABI objects. */
class TransportSignerPolicyTest {
    private fun frame(hashLength: Int, role: String = "client"): ByteArray =
        ByteArray(64) { 0x20 } + "TLS 1.3, $role CertificateVerify".toByteArray(Charsets.US_ASCII) +
            byteArrayOf(0) + ByteArray(hashLength) { it.toByte() }

    @Test fun exactClientFramesWithBothTranscriptHashSizesAreAccepted() {
        for ((hashLength, total) in listOf(32 to 130, 48 to 146)) {
            val bytes = frame(hashLength)
            assertEquals(total, bytes.size)
            assertTrue(ClientCertificateVerifyPolicy.valid(bytes))
            // Hash bytes are opaque, including zero; this is not a text field.
            assertTrue(ClientCertificateVerifyPolicy.valid(bytes.copyOf().also { it.fill(0, 98) }))
        }
    }

    @Test fun serverTls12ApprovalDenialAndPrehashInputsAreRejected() {
        val inputs = listOf(frame(32, "server"), frame(48, "server"),
            "Windows-UAC-Remote-Controller/approve/v1\u0000".toByteArray(),
            "Windows-UAC-Remote-Controller/deny/v1\u0000".toByteArray(),
            "TLS 1.2, client CertificateVerify".toByteArray(), ByteArray(32), ByteArray(48))
        for (bytes in inputs) assertFalse(ClientCertificateVerifyPolicy.valid(bytes))
    }

    @Test fun everyFramingByteIsExactAndNoTruncationOrTrailingByteIsAccepted() {
        val bytes = frame(32)
        for (position in 0 until 98) {
            val changed = bytes.copyOf()
            changed[position] = (changed[position].toInt() xor 1).toByte()
            assertFalse(ClientCertificateVerifyPolicy.valid(changed))
        }
        for (length in 0 until bytes.size) assertFalse(ClientCertificateVerifyPolicy.valid(bytes.copyOf(length)))
        assertFalse(ClientCertificateVerifyPolicy.valid(bytes + byteArrayOf(0)))
        for (length in listOf(0, 1, 31, 33, 47, 49, 64, 512)) {
            assertFalse(ClientCertificateVerifyPolicy.valid(frame(length)))
        }
    }

    @Test fun oneInputMayBeActiveAndCloseKeepsItOccupiedUntilActualReturn() {
        val policy = TransportSignerPolicy()
        assertFalse(policy.isQuiescent())
        assertNull(policy.begin())
        assertTrue(policy.completionAllowed())
        assertEquals(TransportSignerError.BUSY, policy.begin())
        policy.close()
        assertFalse(policy.completionAllowed())
        assertFalse(policy.isQuiescent())
        assertEquals(TransportSignerError.CLOSED, policy.begin())
        policy.returned()
        assertTrue(policy.isQuiescent())
        assertEquals(TransportSignerError.CLOSED, policy.begin())
        policy.close()
        assertTrue(policy.isQuiescent())
    }

    @Test fun separateOneShotInputsDoNotShareAnInFlightOperation() {
        val policy = TransportSignerPolicy()
        repeat(2) {
            assertNull(policy.begin())
            assertTrue(policy.completionAllowed())
            policy.returned()
            assertFalse(policy.completionAllowed())
            assertFalse(policy.isQuiescent())
        }
        policy.close()
        assertTrue(policy.isQuiescent())
    }

    @Test fun closingBeforeFirstUseNeverAllowsAProviderCall() {
        val policy = TransportSignerPolicy()
        policy.close()
        assertTrue(policy.isQuiescent())
        assertEquals(TransportSignerError.CLOSED, policy.begin())
        var rejected = false
        try { policy.returned() } catch (_: IllegalStateException) { rejected = true }
        assertTrue(rejected)
        assertTrue(policy.isQuiescent())
    }

    private class EqualButDifferent {
        override fun equals(other: Any?): Boolean = other is EqualButDifferent
        override fun hashCode(): Int = 1
    }

    @Test fun exactRegistrationAndTransportReferenceMustBothRemainIdentical() {
        val registration = EqualButDifferent()
        val transportReference = EqualButDifferent()
        val captured = TransportReferenceIdentity(registration, transportReference)
        assertTrue(captured.matches(registration, transportReference))
        assertFalse(captured.matches(EqualButDifferent(), transportReference))
        assertFalse(captured.matches(registration, EqualButDifferent()))
        assertFalse(captured.matches(EqualButDifferent(), EqualButDifferent()))
        // Same bytes/alias after release+reopen are not the captured identities.
        assertFalse(captured.matches(transportReference, registration))
        assertEquals("TransportReferenceIdentity([redacted])", captured.toString())
    }

    @Test fun swappedApprovalOrDenialReferenceCannotStandInForCapturedTransportReference() {
        val registration = Any()
        val transport = Any()
        val approval = Any()
        val denial = Any()
        val captured = TransportReferenceIdentity(registration, transport)
        assertFalse(captured.matches(registration, approval))
        assertFalse(captured.matches(registration, denial))
        assertTrue(captured.matches(registration, transport))
    }

    @Test fun outputAndSignerBoundsAreFixedAndDiagnosticsRemainRedacted() {
        assertEquals(32, ClientCertificateVerifyPolicy.MAX_SIGNERS)
        for (length in 8..72) assertTrue(ClientCertificateVerifyPolicy.validDerLength(length))
        for (length in listOf(-1, 0, 7, 73, Int.MAX_VALUE)) assertFalse(ClientCertificateVerifyPolicy.validDerLength(length))
        assertEquals("TransportSignerOutcome.Value([redacted])", TransportSignerOutcome.Value(frame(32)).toString())
        assertEquals("TransportSignerPolicy(lifetime_only)", TransportSignerPolicy().toString())
        // No low-S restriction: canonical DER/scalars and actual signature/key
        // verification are owned by secure-channel, not this size helper.
    }
}
