// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.pairing

/** Public bootstrap carrier only. Rust's existing invitation parser owns meaning. */
internal object PairingUsbFrame {
    const val HEADER = 9
    const val MAX_FRAME = HEADER + 357
    private val magic = byteArrayOf(85, 65, 67, 85, 83, 66, 1) // UACUSB, v1

    fun length(bytes: ByteArray, count: Int): Int? {
        if (count < HEADER || count > MAX_FRAME || bytes.size < count) return null
        if (!magic.indices.all { bytes[it] == magic[it] }) return null
        val body = ((bytes[7].toInt() and 255) shl 8) or (bytes[8].toInt() and 255)
        return if (body == 345 || body == 357) HEADER + body else null
    }

    fun body(bytes: ByteArray, count: Int): ByteArray? {
        if (length(bytes, count) != count) return null
        return bytes.copyOfRange(HEADER, count)
    }
}
