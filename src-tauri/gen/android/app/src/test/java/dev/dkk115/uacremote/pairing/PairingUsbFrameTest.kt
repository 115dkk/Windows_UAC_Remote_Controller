// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.pairing

import org.junit.Assert.*
import org.junit.Test

/** Synthetic framing only, not USB device or enrollment evidence. */
class PairingUsbFrameTest {
    private fun frame(size: Int): ByteArray = byteArrayOf(85, 65, 67, 85, 83, 66, 1,
        (size ushr 8).toByte(), size.toByte()) + ByteArray(size) { 42 }

    @Test fun everyInvitationLengthAndNoOther() {
        // v1 IPv4, v2 IPv4 + one IPv4 alternative, v1 IPv6, v2 IPv6 + three IPv6 alternatives.
        for (size in listOf(345, 353, 357, 415)) {
            val bytes = frame(size)
            assertEquals(bytes.size, PairingUsbFrame.length(bytes, 9))
            assertArrayEquals(ByteArray(size) { 42 }, PairingUsbFrame.body(bytes, bytes.size))
            for (length in 0 until bytes.size) assertNull(PairingUsbFrame.body(bytes, length))
            val extra = bytes + 0.toByte()
            assertNull(PairingUsbFrame.body(extra, extra.size))
        }
    }

    @Test fun everyHeaderByteIsChecked() {
        for (at in 0..8) {
            val bytes = frame(345)
            bytes[at] = (bytes[at].toInt() xor 128).toByte()
            assertNull(PairingUsbFrame.body(bytes, bytes.size))
        }
        for (size in listOf(0, 344, 416, 65535)) assertNull(PairingUsbFrame.length(frame(size), 9))
        assertNull(PairingUsbFrame.body(frame(346), 354))
        assertNull(PairingUsbFrame.body(ByteArray(0), Int.MAX_VALUE))
        assertNull(PairingUsbFrame.body(frame(345), -1))
    }

    @Test fun qrPrefixFollowsTheBodyVersion() {
        fun body(version: Int) = ByteArray(353).also { it[8] = 0; it[9] = version.toByte() }
        assertEquals("uac-remote:v1:", PairingUsbFrame.qrPrefix(body(1)))
        assertEquals("uac-remote:v2:", PairingUsbFrame.qrPrefix(body(2)))
    }
}
