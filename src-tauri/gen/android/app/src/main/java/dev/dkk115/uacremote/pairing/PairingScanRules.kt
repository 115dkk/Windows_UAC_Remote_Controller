// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.pairing

import java.nio.ByteBuffer
import java.util.concurrent.atomic.AtomicBoolean

internal enum class PairingScannerLaunch(val wireValue: String) { OPENED("opened"), BUSY("busy"), UNAVAILABLE("unavailable") }
internal enum class PairingScanStart { READY, BUSY, UNAVAILABLE }
internal enum class PairingScanRead { READ, INVALID, UNAVAILABLE }
internal enum class PairingScannerState { PREPARING, PERMISSION_PENDING, PERMISSION_DENIED, PERMISSION_SETTINGS, CAMERA_UNAVAILABLE, UNAVAILABLE, SCANNING, READING, READ, INVALID, EXPIRED, CLOSED }

/** Process-local selection only. It owns no keys, peer, original fields or permission. */
internal class PairingScanTicket {
    private val cancelled = AtomicBoolean(false)
    fun cancel() { cancelled.set(true) }
    fun isCancelled(): Boolean = cancelled.get()
    override fun toString(): String = "PairingScanTicket([redacted])"
}

/** Main-owned window release observation; callbacks never establish API return. */
internal class PairingWindowRelease {
    private var attempted = false
    private var returned = false
    private var uncertain = false
    fun beginDismiss(): Boolean {
        if (attempted) return false
        attempted = true // Before the only underlying dismiss API invocation.
        return true
    }
    fun returnedNormally() { if (attempted && !uncertain) returned = true }
    fun failed() { uncertain = true }
    fun complete(showing: Boolean?, originalDecorAttached: Boolean?): Boolean =
        attempted && returned && !uncertain && showing == false && originalDecorAttached == false
    override fun toString(): String = "PairingWindowRelease([redacted])"
}

internal object PairingScanRules {
    const val LIFETIME_MILLIS = 300_000L
    const val MAX_QR_CHARS = 490
    fun current(started: Long, now: Long): Boolean =
        started >= 0 && now >= started && now - started < LIFETIME_MILLIS
    fun expired(started: Long, now: Long): Boolean =
        started >= 0 && now >= started && now - started >= LIFETIME_MILLIS
    fun boundedText(text: String): Boolean = (text.length == 474 || text.length == MAX_QR_CHARS) && text.all { it.code in 0..127 }
}

/** Copy only a bounded Y plane. No file, camera, decoder, rotation transform or credentials. */
internal object QrLuminance {
    const val MAX_SIDE = 1280
    const val MAX_PIXELS = MAX_SIDE * MAX_SIDE
    const val MAX_PLANE_BYTES = 8 * 1024 * 1024
    fun copy(width: Int, height: Int, rowStride: Int, pixelStride: Int, rotation: Int, input: ByteBuffer): ByteArray? {
        if (width !in 1..MAX_SIDE || height !in 1..MAX_SIDE || rotation !in setOf(0, 90, 180, 270) ||
            pixelStride !in 1..4 || rowStride !in 1..8192 || input.remaining() !in 1..MAX_PLANE_BYTES) return null
        val rowBytes = (width - 1L) * pixelStride + 1L
        val last = input.position().toLong() + (height - 1L) * rowStride + rowBytes - 1L
        val count = width.toLong() * height
        if (rowBytes > rowStride || last >= input.limit().toLong() || count > MAX_PIXELS) return null
        val source = input.asReadOnlyBuffer()
        val base = source.position()
        return ByteArray(count.toInt()).also { output ->
            for (row in 0 until height) for (column in 0 until width) {
                output[row * width + column] = source.get(base + row * rowStride + column * pixelStride)
            }
        }
    }
}
