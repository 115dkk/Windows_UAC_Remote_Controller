// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.pairing

import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.NotFoundException
import com.google.zxing.ChecksumException
import com.google.zxing.FormatException
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeReader

internal sealed class OfflineQrResult {
    object Absent : OfflineQrResult()
    object Invalid : OfflineQrResult()
    class Text(val value: String) : OfflineQrResult()
    final override fun toString(): String = "OfflineQrResult([redacted])"
}

/** One decoder instance per bounded camera worker. QR only; no network/module download. */
internal class OfflineQrDecoder {
    private val reader = QRCodeReader()
    fun decode(luminance: ByteArray, width: Int, height: Int): OfflineQrResult {
        if (width !in 1..QrLuminance.MAX_SIDE || height !in 1..QrLuminance.MAX_SIDE ||
            width.toLong() * height != luminance.size.toLong()) return OfflineQrResult.Invalid
        return try {
            val source = PlanarYUVLuminanceSource(luminance, width, height, 0, 0, width, height, false)
            val result = reader.decode(BinaryBitmap(HybridBinarizer(source)), mapOf(DecodeHintType.TRY_HARDER to true))
            val text = result.text
            if (text == null || !PairingScanRules.boundedText(text)) OfflineQrResult.Invalid else OfflineQrResult.Text(text)
        } catch (_: NotFoundException) { OfflineQrResult.Absent }
        catch (_: ChecksumException) { OfflineQrResult.Absent }
        catch (_: FormatException) { OfflineQrResult.Absent }
        finally { reader.reset() }
    }
    override fun toString(): String = "OfflineQrDecoder([redacted])"
}
