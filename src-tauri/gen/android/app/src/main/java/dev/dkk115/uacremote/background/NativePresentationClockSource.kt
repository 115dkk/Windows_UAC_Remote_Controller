// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.background

import android.os.Looper
import android.os.SystemClock
import dev.dkk115.uacremote.nativecore.BridgeException
import dev.dkk115.uacremote.nativecore.NativePresentationClock
import java.time.Instant
import java.time.ZoneId
import java.util.TimeZone

internal enum class PresentationClockAvailability { READY, REFRESH_REQUIRED, UNAVAILABLE }

/** Observations only. Rust still evaluates schedule, original expiry and authority. */
internal object PresentationClockRules {
    const val MAX_SPAN_NANOS = 100_000_000L
    fun availability(knownBoot: Boolean, knownZone: Boolean, warm: Boolean, closed: Boolean, faulted: Boolean): PresentationClockAvailability = when {
        !knownBoot || !knownZone || closed || faulted -> PresentationClockAvailability.UNAVAILABLE
        !warm -> PresentationClockAvailability.REFRESH_REQUIRED
        else -> PresentationClockAvailability.READY
    }
    fun valid(before: Long, after: Long, wallBefore: Long, wallAfter: Long): Boolean {
        if (before < 0 || after < before || after - before > MAX_SPAN_NANOS || wallBefore < 0 || wallAfter < wallBefore) return false
        val roundedSpanMillis = (after - before + 999_999L) / 1_000_000L
        if (wallAfter - wallBefore > roundedSpanMillis + 1L) return false
        val wallNanos = (wallAfter - wallBefore) * 1_000_000L
        val span = after - before
        return if (wallNanos >= span) wallNanos - span <= 2_000_000L else span - wallNanos <= 2_000_000L
    }
    fun consistentPrevious(elapsed: Long, wall: Long, previousElapsed: Long, previousWall: Long): Boolean {
        if (elapsed < previousElapsed || wall < previousWall) return false
        val elapsedMillis = (elapsed - previousElapsed) / 1_000_000L
        val wallMillis = wall - previousWall
        return if (wallMillis >= elapsedMillis) wallMillis - elapsedMillis <= 2L else elapsedMillis - wallMillis <= 2L
    }
}

/** Worker warms zone rules and binds the already-observed boot. Reads use only
 * cached rules plus native clocks/default-zone identity: no settings/key/store
 * lookup, no worker wait, and no fallback clock on the main thread. */
internal class NativePresentationClockSource(private val changed: () -> Unit) {
    private val lock = Any()
    private var boot: Int? = null
    private var zone: ZoneId? = null
    private var epoch = 1L
    private var warm = false
    private var closed = false
    private var faulted = false
    private var lastElapsed: Long? = null
    private var lastWall: Long? = null

    fun warm(bootCount: Int) {
        if (Looper.myLooper() == Looper.getMainLooper() || bootCount < 0) throw BridgeException.NativeUnavailable()
        val currentZone = ZoneId.systemDefault()
        val now = System.currentTimeMillis()
        if (now < 0) throw BridgeException.InvalidObservation()
        currentZone.rules.getOffset(Instant.ofEpochMilli(now)) // May initialize provider data ONLY here.
        Instant.ofEpochMilli(now).atZone(currentZone).dayOfWeek.value
        val notify = synchronized(lock) {
            if (closed || faulted || (boot != null && boot != bootCount)) throw BridgeException.InvalidObservation()
            if (warm && zone?.id == currentZone.id) return
            val changedZone = warm && zone != null && zone?.id != currentZone.id
            if (changedZone) {
                if (epoch == Long.MAX_VALUE) { faulted = true; throw BridgeException.InvalidObservation() }
                epoch += 1
            }
            boot = bootCount; zone = currentZone; warm = true; lastWall = null
            changedZone
        }
        if (notify) try { changed() } catch (_: Exception) { }
    }

    fun invalidate() {
        val notify = synchronized(lock) {
            if (closed || faulted || !warm) false
            else {
                if (epoch == Long.MAX_VALUE) faulted = true else epoch += 1
                warm = false; lastWall = null
                true
            }
        }
        if (notify) try { changed() } catch (_: Exception) { }
    }

    fun close() = synchronized(lock) { closed = true; warm = false }

    fun observe(): NativePresentationClock {
        var notify = false
        var refreshNeeded = false
        val result = synchronized(lock) {
            val currentBoot = boot; val currentZone = zone
            when (PresentationClockRules.availability(currentBoot != null, currentZone != null, warm, closed, faulted)) {
                PresentationClockAvailability.REFRESH_REQUIRED -> throw BridgeException.PresentationRefreshRequired()
                PresentationClockAvailability.UNAVAILABLE -> throw BridgeException.NativeUnavailable()
                PresentationClockAvailability.READY -> Unit
            }
            if (currentBoot == null || currentZone == null) throw BridgeException.NativeUnavailable()
            // Serialize the LIGHT sample state only, so two callers completing
            // in a different order cannot manufacture monotonic regression.
            val zoneBefore = TimeZone.getDefault().id
            val elapsedBefore = SystemClock.elapsedRealtimeNanos()
            val wallBefore = System.currentTimeMillis()
            val wallAfter = System.currentTimeMillis()
            val elapsedAfter = SystemClock.elapsedRealtimeNanos()
            val zoneAfter = TimeZone.getDefault().id
            val previousElapsed = lastElapsed; val previousWall = lastWall
            val regressed = previousElapsed != null && elapsedAfter < previousElapsed
            val invalidNativeShape = elapsedBefore < 0 || elapsedAfter < elapsedBefore || wallBefore < 0 || wallAfter < 0
            val valid = PresentationClockRules.valid(elapsedBefore, elapsedAfter, wallBefore, wallAfter) &&
                zoneBefore == currentZone.id && zoneAfter == zoneBefore && !regressed &&
                (previousElapsed == null || previousWall == null || PresentationClockRules.consistentPrevious(elapsedAfter, wallAfter, previousElapsed, previousWall))
            if (!valid) {
                if (regressed || invalidNativeShape || epoch == Long.MAX_VALUE) faulted = true else epoch += 1
                warm = false; lastWall = null; notify = true; refreshNeeded = !faulted
                null
            } else {
                val local = Instant.ofEpochMilli(wallAfter).atZone(currentZone)
                lastElapsed = elapsedAfter; lastWall = wallAfter
                NativePresentationClock(
                    bootCount = currentBoot.toUInt(), elapsedBeforeNanos = elapsedBefore.toULong(), elapsedAfterNanos = elapsedAfter.toULong(),
                    wallBeforeMillis = wallBefore.toULong(), wallAfterMillis = wallAfter.toULong(),
                    weekday = (local.dayOfWeek.value - 1).toUByte(), minute = (local.hour * 60 + local.minute).toUShort(),
                    millisWithinMinute = (local.second * 1000 + local.nano / 1_000_000).toUShort(), timeEpoch = epoch.toULong(),
                )
            }
        }
        if (notify) try { changed() } catch (_: Exception) { }
        if (result != null) return result
        // Preserve the classification of THIS rejected sample even if the
        // queued worker has already re-warmed by the time the callback returns.
        if (refreshNeeded) throw BridgeException.PresentationRefreshRequired()
        throw BridgeException.InvalidObservation()
    }
    override fun toString(): String = "NativePresentationClockSource(observations_only)"
}
