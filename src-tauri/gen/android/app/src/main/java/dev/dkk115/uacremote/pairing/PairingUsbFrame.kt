// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.pairing

import android.util.Base64

/** Public bootstrap carrier only. Rust's existing invitation parser owns meaning. */
internal object PairingUsbFrame {
    const val HEADER = 9
    // Mirrors service_protocol's MIN/MAX_PAIRING_INVITATION_BYTES: v1 is 345 or
    // 357 bytes, v2 adds up to three alternative endpoints. Rust checks the exact form.
    const val MIN_BODY = 345
    const val MAX_BODY = 415
    const val MAX_FRAME = HEADER + MAX_BODY
    private val magic = byteArrayOf(85, 65, 67, 85, 83, 66, 1) // UACUSB, v1

    fun length(bytes: ByteArray, count: Int): Int? {
        if (count < HEADER || count > MAX_FRAME || bytes.size < count) return null
        if (!magic.indices.all { bytes[it] == magic[it] }) return null
        val body = ((bytes[7].toInt() and 255) shl 8) or (bytes[8].toInt() and 255)
        return if (body in MIN_BODY..MAX_BODY) HEADER + body else null
    }

    fun body(bytes: ByteArray, count: Int): ByteArray? {
        if (length(bytes, count) != count) return null
        return bytes.copyOfRange(HEADER, count)
    }

    /** The QR prefix names the body's version (bytes 8..9); Rust rejects a mismatch. */
    fun qrPrefix(body: ByteArray): String =
        if (body.size > 9 && body[8].toInt() == 0 && body[9].toInt() == 2) "uac-remote:v2:" else "uac-remote:v1:"

    fun invitationText(body: ByteArray): String =
        qrPrefix(body) + Base64.encodeToString(body, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
}
