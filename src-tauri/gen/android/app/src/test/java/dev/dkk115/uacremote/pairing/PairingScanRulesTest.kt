// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.pairing

import com.google.zxing.BarcodeFormat
import com.google.zxing.MultiFormatWriter
import org.junit.Assert.*
import org.junit.Test
import java.nio.ByteBuffer

/** Synthetic local contracts only; no camera, original invitation, native owner or enrollment proof. */
class PairingScanRulesTest {
    @Test fun scannerStatesKeepTheExactGalleryOrder() {
        assertEquals(listOf(
            "PREPARING", "PERMISSION_PENDING", "PERMISSION_DENIED", "PERMISSION_SETTINGS",
            "CAMERA_UNAVAILABLE", "UNAVAILABLE", "SCANNING", "READING", "READ", "CONNECTING",
            "COMPARE", "WAITING_PC", "ENROLLED", "FAILED", "INVALID", "EXPIRED", "CLOSED",
        ), PairingScannerState.values().map { it.name })
    }

    @Test fun comparisonRequiresExactlySixAsciiDigitsWithoutRepair() {
        assertEquals(PairingScannerState.UNAVAILABLE, PairingScannerCopy.resolvedState(PairingScannerState.COMPARE))
        for (code in listOf(null, "", "12345", "1234567", "123 456", "12345a", "１２３４５６", "١٢٣٤٥٦", " 123456", "123456\n")) {
            assertEquals(PairingScannerState.UNAVAILABLE, PairingScannerCopy.resolvedState(PairingScannerState.COMPARE, code))
        }
        for (code in listOf("123456", "000000", "012345", "987654")) {
            assertEquals(PairingScannerState.COMPARE, PairingScannerCopy.resolvedState(PairingScannerState.COMPARE, code))
        }
        for (state in PairingScannerState.values().filter { it != PairingScannerState.COMPARE }) {
            assertEquals(state, PairingScannerCopy.resolvedState(state))
            assertEquals(state, PairingScannerCopy.resolvedState(state, "invalid"))
        }
    }

    @Test fun comparisonCopyGroupsAsciiDigitsAndLocalizesOnlyTheirSpokenNames() {
        assertEquals("123 456", PairingScannerCopy.groupedCode("123456"))
        assertEquals("one, two, three, four, five, six", PairingScannerCopy.codeDescription("123456"))
        assertEquals("007 890", PairingScannerCopy.groupedCode("007890"))
        assertEquals("zero, zero, seven, eight, nine, zero", PairingScannerCopy.codeDescription("007890"))
        assertEquals("영, 영, 칠, 팔, 구, 영", PairingScannerCopy.codeDescription("007890",
            listOf("영", "일", "이", "삼", "사", "오", "육", "칠", "팔", "구")))
        assertEquals("صفر, واحد, اثنان, ثلاثة, أربعة, خمسة", PairingScannerCopy.codeDescription("012345",
            listOf("صفر", "واحد", "اثنان", "ثلاثة", "أربعة", "خمسة", "ستة", "سبعة", "ثمانية", "تسعة")))
    }

    @Test fun comparisonCopyRejectsMalformedDigitsBeforeFormatting() {
        for (code in listOf("", "12345", "1234567", "123 456", "12345a", "１２３４５６", "١٢٣٤٥٦", " 123456", "123456\n")) {
            try {
                PairingScannerCopy.groupedCode(code)
                fail("Malformed comparison code must not be grouped")
            } catch (_: IllegalArgumentException) { }
            try {
                PairingScannerCopy.codeDescription(code)
                fail("Malformed comparison code must not be announced")
            } catch (_: IllegalArgumentException) { }
        }
    }

    @Test fun originalLocalDeadlineNeverRenewsAndRegressionIsNotExpiry() {
        assertTrue(PairingScanRules.current(100, 300_099))
        assertFalse(PairingScanRules.current(100, 300_100))
        assertTrue(PairingScanRules.expired(100, 300_100))
        for ((start, now) in listOf(-1L to 0L, 100L to 99L, 100L to -1L)) {
            assertFalse(PairingScanRules.current(start, now))
            assertFalse(PairingScanRules.expired(start, now))
        }
        assertTrue(PairingScanRules.current(Long.MAX_VALUE - 1, Long.MAX_VALUE))
        assertTrue(PairingScanRules.expired(0, Long.MAX_VALUE))
    }

    @Test fun ticketCancellationIsIrreversibleAndCannotSelectAnotherTicket() {
        val first = PairingScanTicket(); val other = PairingScanTicket()
        first.cancel(); first.cancel()
        assertTrue(first.isCancelled()); assertFalse(other.isCancelled())
        assertEquals("PairingScanTicket([redacted])", first.toString())
    }

    @Test fun windowCallbackOrDetachedDecorCannotReplaceTheOnlySuccessfulDismissReturn() {
        val release = PairingWindowRelease()
        assertFalse(release.complete(false, false))
        assertTrue(release.beginDismiss())
        // onDismiss/detach can happen reentrantly before the API returns.
        assertFalse(release.complete(false, false))
        assertFalse(release.beginDismiss())
        release.returnedNormally()
        assertFalse(release.complete(true, false))
        assertFalse(release.complete(false, true))
        assertFalse(release.complete(null, false))
        assertFalse(release.complete(false, null))
        assertTrue(release.complete(false, false))
    }

    @Test fun dismissalFailureRemainsUncertainAfterCallbacksAndCannotAutomaticallyRetry() {
        val release = PairingWindowRelease()
        assertTrue(release.beginDismiss())
        assertFalse(release.complete(false, false)) // SDK callback precedes exception.
        release.failed()
        release.returnedNormally() // A later callback cannot repair uncertainty.
        assertFalse(release.complete(false, false))
        assertFalse(release.beginDismiss())
    }

    @Test fun neverShownOrAlreadyDetachedWindowStillRequiresTheOneNormalDismissReturn() {
        for (alreadyDetached in listOf(false, true)) {
            val release = PairingWindowRelease()
            assertTrue(release.beginDismiss())
            assertFalse(release.complete(false, false))
            release.returnedNormally()
            assertEquals(alreadyDetached, release.complete(false, !alreadyDetached))
            assertTrue(release.complete(false, false))
        }
    }

    @Test fun foreignTextBoundIsOnlyAsciiSizeNotCanonicalAcceptance() {
        assertTrue(PairingScanRules.boundedText("A".repeat(474)))
        assertTrue(PairingScanRules.boundedText("A".repeat(490)))
        for (text in listOf("", "A".repeat(473), "A".repeat(475), "A".repeat(491), "가".repeat(474))) {
            assertFalse(PairingScanRules.boundedText(text))
        }
    }

    @Test fun yPlaneHonorsPositionRowPaddingPixelStrideAndDoesNotMutateNativeBuffer() {
        val input = ByteBuffer.wrap(ByteArray(16) { it.toByte() }).apply { position(1) }
        val copied = QrLuminance.copy(3, 2, 8, 2, 90, input)
        assertArrayEquals(byteArrayOf(1, 3, 5, 9, 11, 13), copied)
        assertEquals(1, input.position()); assertEquals(16, input.limit())
        copied?.fill(0)
        assertEquals(1.toByte(), input.get(1))
    }

    @Test fun dimensionsStridesAndLastByteAreBoundedBeforeAllocation() {
        val input = ByteBuffer.allocate(16)
        for ((width, height, row, pixel, rotation) in listOf(
            listOf(0, 1, 1, 1, 0), listOf(1, 0, 1, 1, 0), listOf(1281, 1, 1281, 1, 0),
            listOf(Int.MAX_VALUE, Int.MAX_VALUE, Int.MAX_VALUE, Int.MAX_VALUE, 0),
            listOf(3, 2, 4, 2, 0), listOf(3, 3, 8, 1, 0), listOf(1, 1, 0, 1, 0),
            listOf(1, 1, 1, 0, 0), listOf(1, 1, 4, 5, 0), listOf(1, 1, 1, 1, 45))) {
            assertNull(QrLuminance.copy(width, height, row, pixel, rotation, input))
        }
        assertNull(QrLuminance.copy(1, 1, 1, 1, 0, ByteBuffer.allocate(0)))
        assertNull(QrLuminance.copy(1, 1, 1, 1, 0, ByteBuffer.allocate(QrLuminance.MAX_PLANE_BYTES + 1)))
        for (rotation in listOf(0, 90, 180, 270)) assertNotNull(QrLuminance.copy(4, 4, 4, 1, rotation, input))
    }

    @Test fun bundledQrOnlyDecoderReturnsBoundedNativeTextAndRedactsIt() {
        // This is deliberately not a valid original ceremony. Rust owns its
        // independent canonical parser/admission; no native acceptance is called.
        val text = "uac-remote:v1:" + "A".repeat(460)
        val pixels = encoded(text, BarcodeFormat.QR_CODE)
        val result = OfflineQrDecoder().decode(pixels, 512, 512)
        assertTrue(result is OfflineQrResult.Text)
        assertEquals(text, (result as OfflineQrResult.Text).value)
        assertEquals("OfflineQrResult([redacted])", result.toString())
        pixels.fill(0)
    }

    @Test fun nonQrBlankAndNonInvitationQrDoNotBecomeAcceptedInput() {
        val decoder = OfflineQrDecoder()
        assertSame(OfflineQrResult.Absent, decoder.decode(ByteArray(512 * 512) { 255.toByte() }, 512, 512))
        assertSame(OfflineQrResult.Absent, decoder.decode(encoded("synthetic-only", BarcodeFormat.CODE_128), 512, 512))
        assertSame(OfflineQrResult.Invalid, decoder.decode(encoded("synthetic-not-an-invitation", BarcodeFormat.QR_CODE), 512, 512))
        assertSame(OfflineQrResult.Invalid, decoder.decode(ByteArray(1), Int.MAX_VALUE, 2))
    }

    private fun encoded(text: String, format: BarcodeFormat): ByteArray {
        val bits = MultiFormatWriter().encode(text, format, 512, 512)
        return ByteArray(512 * 512) { index -> if (bits[index % 512, index / 512]) 0.toByte() else 255.toByte() }
    }
}
