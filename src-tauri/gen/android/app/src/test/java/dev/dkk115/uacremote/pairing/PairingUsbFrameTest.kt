// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.pairing

import org.junit.Assert.*
import org.junit.Test

/** Synthetic framing only, not USB device or enrollment evidence. */
class PairingUsbFrameTest {
    private fun frame(size: Int): ByteArray = byteArrayOf(85, 65, 67, 85, 83, 66, 1,
        (size ushr 8).toByte(), size.toByte()) + ByteArray(size) { 42 }

    @Test fun exactCanonicalLengthsOnly() {
        for (size in listOf(345, 357)) {
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
        assertNull(PairingUsbFrame.body(frame(346), 355))
        assertNull(PairingUsbFrame.body(ByteArray(0), Int.MAX_VALUE))
        assertNull(PairingUsbFrame.body(frame(345), -1))
    }
}
