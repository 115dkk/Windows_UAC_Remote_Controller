// SPDX-License-Identifier: GPL-2.0-or-later

package dev.dkk115.uacremote.background

import android.app.Application
import android.os.Looper
import android.os.SystemClock
import android.os.UserManager
import android.provider.Settings
import java.io.File
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.NoSuchFileException
import java.nio.file.attribute.BasicFileAttributes
import java.time.ZoneId
import java.time.ZonedDateTime

/** Credential-encrypted storage availability, NOT screen-lock/authentication state. */
internal enum class CredentialStorageState { AVAILABLE, LOCKED }

/** Fixed categories only; no paths, provider messages or exception objects cross the boundary. */
internal enum class NativeEnvironmentError {
    WRONG_THREAD,
    BOOT_COUNT_UNAVAILABLE,
    INVALID_BOOT_COUNT,
    ELAPSED_TIME_UNAVAILABLE,
    INVALID_ELAPSED_TIME,
    LOCAL_TIME_UNAVAILABLE,
    INVALID_LOCAL_TIME,
    CREDENTIAL_STORAGE_UNAVAILABLE,
    CREDENTIAL_STORAGE_LOCKED,
    UNSTABLE_OBSERVATION,
    READ_SPAN_TOO_LONG,
    OBSERVATION_UNAVAILABLE,
    DEVICE_PROTECTED_CONTEXT,
    DIRECTORY_UNAVAILABLE,
    DIRECTORY_UNSAFE_ENTRY,
    DIRECTORY_CREATE_FAILED,
}

internal sealed class NativeEnvironmentOutcome<out T> {
    class Value<T>(val value: T) : NativeEnvironmentOutcome<T>()
    class Failure(val error: NativeEnvironmentError) : NativeEnvironmentOutcome<Nothing>()

    final override fun toString(): String = when (this) {
        is Value -> "NativeEnvironmentOutcome.Value([redacted])"
        is Failure -> "NativeEnvironmentOutcome.Failure($error)"
    }
}

/**
 * Plain native observations for a future Rust adapter, not an authorization DTO.
 * elapsedRealtimeNanos is sampled between matching local/boot observations.
 * readCompletedElapsedRealtimeNanos exposes sampling age; Rust owns all lifetime,
 * schedule, projection and post-I/O freshness decisions. Neither timestamp is an
 * atomic snapshot of every Android service or a native-action permit.
 */
internal data class NativeEnvironmentSnapshot(
    val bootCount: Int,
    val elapsedRealtimeNanos: Long,
    val elapsedRealtimeMillis: Long,
    val weekdayMondayZero: Int,
    val minuteOfDay: Int,
    val credentialStorage: CredentialStorageState,
    val readCompletedElapsedRealtimeNanos: Long,
    val readSpanNanos: Long,
) {
    override fun toString(): String = "NativeEnvironmentSnapshot(native_observations)"
}

/** Native-provider output only. A string/DTO alone cannot prove filesystem ownership. */
internal class NativeStateDirectory internal constructor(val canonicalPath: String) {
    override fun toString(): String = "NativeStateDirectory(native_app_private_path)"
}

/** Full local-date/minute/zone comparison prevents a repeated weekday/minute hiding a jump. */
internal data class LocalEnvironmentObservation(
    val epochDay: Long,
    val isoWeekday: Int,
    val hour: Int,
    val minute: Int,
    val zoneId: String,
    val offsetSeconds: Int,
) {
    override fun toString(): String = "LocalEnvironmentObservation(native_local_time)"
}

/** Pure metadata seam for tests; constructing it does not make Android observations. */
internal data class NativeEnvironmentRead(
    val startedNanos: Long,
    val sampledNanos: Long,
    val completedNanos: Long,
    val bootBefore: Int,
    val bootAfter: Int,
    val localBefore: LocalEnvironmentObservation,
    val localAfter: LocalEnvironmentObservation,
    val storageBefore: CredentialStorageState,
    val storageAfter: CredentialStorageState,
) {
    override fun toString(): String = "NativeEnvironmentRead(native_observations)"
}

/** Observation shape/coherence only. No notification policy or authentication is evaluated. */
internal object NativeEnvironmentRules {
    const val MAX_READ_ATTEMPTS = 3
    const val MAX_READ_SPAN_NANOS = 100_000_000L
    const val NANOS_PER_MILLI = 1_000_000L
    const val DIRECTORY_NAME = "controller-state"

    fun weekdayMondayZero(isoWeekday: Int): Int? =
        if (isoWeekday in 1..7) isoWeekday - 1 else null

    fun minuteOfDay(hour: Int, minute: Int): Int? =
        if (hour in 0..23 && minute in 0..59) hour * 60 + minute else null

    fun elapsedMillis(nanos: Long): Long? =
        if (nanos >= 0) nanos / NANOS_PER_MILLI else null

    fun snapshot(read: NativeEnvironmentRead): NativeEnvironmentOutcome<NativeEnvironmentSnapshot> {
        if (read.bootBefore < 0 || read.bootAfter < 0) {
            return NativeEnvironmentOutcome.Failure(NativeEnvironmentError.INVALID_BOOT_COUNT)
        }
        if (!validLocal(read.localBefore) || !validLocal(read.localAfter)) {
            return NativeEnvironmentOutcome.Failure(NativeEnvironmentError.INVALID_LOCAL_TIME)
        }
        if (read.startedNanos < 0 || read.sampledNanos < read.startedNanos ||
            read.completedNanos < read.sampledNanos) {
            return NativeEnvironmentOutcome.Failure(NativeEnvironmentError.INVALID_ELAPSED_TIME)
        }
        if (read.bootBefore != read.bootAfter || read.localBefore != read.localAfter ||
            read.storageBefore != read.storageAfter) {
            return NativeEnvironmentOutcome.Failure(NativeEnvironmentError.UNSTABLE_OBSERVATION)
        }
        // Ordered nonnegative Long values make subtraction non-overflowing.
        // Equal reads are valid when the native clock has coarser resolution.
        val span = read.completedNanos - read.startedNanos
        if (span > MAX_READ_SPAN_NANOS) {
            return NativeEnvironmentOutcome.Failure(NativeEnvironmentError.READ_SPAN_TOO_LONG)
        }
        return NativeEnvironmentOutcome.Value(NativeEnvironmentSnapshot(
            bootCount = read.bootBefore,
            elapsedRealtimeNanos = read.sampledNanos,
            elapsedRealtimeMillis = read.sampledNanos / NANOS_PER_MILLI,
            weekdayMondayZero = read.localBefore.isoWeekday - 1,
            minuteOfDay = read.localBefore.hour * 60 + read.localBefore.minute,
            credentialStorage = read.storageBefore,
            readCompletedElapsedRealtimeNanos = read.completedNanos,
            readSpanNanos = span,
        ))
    }

    fun mayRetry(error: NativeEnvironmentError): Boolean =
        error == NativeEnvironmentError.UNSTABLE_OBSERVATION ||
            error == NativeEnvironmentError.READ_SPAN_TOO_LONG

    fun directoryEntryError(isDirectory: Boolean, isSymbolicLink: Boolean): NativeEnvironmentError? =
        if (!isDirectory || isSymbolicLink) NativeEnvironmentError.DIRECTORY_UNSAFE_ENTRY else null

    private fun validLocal(local: LocalEnvironmentObservation): Boolean =
        weekdayMondayZero(local.isoWeekday) != null && minuteOfDay(local.hour, local.minute) != null &&
            local.zoneId.isNotEmpty() && local.zoneId.length <= 255 &&
            local.offsetSeconds in -64_800..64_800
}

/**
 * Headless Application-only provider. Construction stores the Application and
 * performs no Android/storage observation, key operation or initialization.
 * Both methods belong on the native background owner, never the main thread.
 * No Activity, caller paths, fallback clocks or alternate storage contexts exist.
 */
internal class NativeEnvironment(private val application: Application) {
    fun observe(): NativeEnvironmentOutcome<NativeEnvironmentSnapshot> = try {
        requireBackgroundThread()
        var lastFailure = NativeEnvironmentError.UNSTABLE_OBSERVATION
        var accepted: NativeEnvironmentOutcome<NativeEnvironmentSnapshot>? = null
        var remainingAttempts = NativeEnvironmentRules.MAX_READ_ATTEMPTS
        while (remainingAttempts > 0) {
            remainingAttempts -= 1
            val started = readElapsed()
            val firstBoot = readBootCount()
            val firstLocal = readLocal()
            val firstStorage = readCredentialStorage()
            val sampled = readElapsed()
            val secondStorage = readCredentialStorage()
            val secondLocal = readLocal()
            val secondBoot = readBootCount()
            val completed = readElapsed()
            when (val result = NativeEnvironmentRules.snapshot(NativeEnvironmentRead(
                started, sampled, completed, firstBoot, secondBoot, firstLocal, secondLocal,
                firstStorage, secondStorage,
            ))) {
                is NativeEnvironmentOutcome.Value -> { accepted = result; break }
                is NativeEnvironmentOutcome.Failure -> {
                    lastFailure = result.error
                    if (!NativeEnvironmentRules.mayRetry(result.error)) break
                }
            }
        }
        accepted ?: NativeEnvironmentOutcome.Failure(lastFailure)
    } catch (failure: EnvironmentFailure) {
        NativeEnvironmentOutcome.Failure(failure.error)
    } catch (_: Exception) {
        NativeEnvironmentOutcome.Failure(NativeEnvironmentError.OBSERVATION_UNAVAILABLE)
    }

    fun controllerDirectory(): NativeEnvironmentOutcome<NativeStateDirectory> = try {
        requireBackgroundThread()
        if (application.isDeviceProtectedStorage) fail(NativeEnvironmentError.DEVICE_PROTECTED_CONTEXT)
        requireCredentialStorage()
        val nativeBase: File = application.noBackupFilesDir
        if (!nativeBase.isAbsolute) fail(NativeEnvironmentError.DIRECTORY_UNSAFE_ENTRY)
        requireDirectory(nativeBase)

        // Android may supply trusted OS-owned parent aliases such as /data/user/0.
        // Resolve those, but never accept a symlink as noBackup's own final entry.
        val canonicalBase = nativeBase.canonicalFile
        requireDirectory(canonicalBase)
        val expectedChild = File(canonicalBase, NativeEnvironmentRules.DIRECTORY_NAME)
        if (readEntryIfPresent(expectedChild) == null && !expectedChild.mkdir()) {
            fail(NativeEnvironmentError.DIRECTORY_CREATE_FAILED)
        }
        requireDirectory(expectedChild)
        val canonicalChild = expectedChild.canonicalFile
        if (canonicalChild != expectedChild || canonicalChild.parentFile != canonicalBase ||
            canonicalChild.name != NativeEnvironmentRules.DIRECTORY_NAME) {
            fail(NativeEnvironmentError.DIRECTORY_UNSAFE_ENTRY)
        }
        // Recheck both final entries and base resolution after the only mkdir.
        requireDirectory(nativeBase)
        requireDirectory(canonicalBase)
        requireDirectory(expectedChild)
        if (nativeBase.canonicalFile != canonicalBase || expectedChild.canonicalFile != canonicalChild) {
            fail(NativeEnvironmentError.DIRECTORY_UNSAFE_ENTRY)
        }
        requireCredentialStorage()
        NativeEnvironmentOutcome.Value(NativeStateDirectory(canonicalChild.path))
    } catch (failure: EnvironmentFailure) {
        NativeEnvironmentOutcome.Failure(failure.error)
    } catch (_: Exception) {
        NativeEnvironmentOutcome.Failure(NativeEnvironmentError.DIRECTORY_UNAVAILABLE)
    }

    private fun requireBackgroundThread() {
        if (Looper.myLooper() == Looper.getMainLooper()) fail(NativeEnvironmentError.WRONG_THREAD)
    }

    private fun readBootCount(): Int {
        // The no-default overload throws for missing/malformed settings. Zero is
        // a valid observed count and must never stand in for an observation error.
        val count = try {
            Settings.Global.getInt(application.contentResolver, Settings.Global.BOOT_COUNT)
        } catch (_: Exception) {
            fail(NativeEnvironmentError.BOOT_COUNT_UNAVAILABLE)
        }
        if (count < 0) fail(NativeEnvironmentError.INVALID_BOOT_COUNT)
        return count
    }

    private fun readElapsed(): Long = try {
        SystemClock.elapsedRealtimeNanos()
    } catch (_: Exception) {
        fail(NativeEnvironmentError.ELAPSED_TIME_UNAVAILABLE)
    }

    private fun readLocal(): LocalEnvironmentObservation = try {
        val local = ZonedDateTime.now(ZoneId.systemDefault())
        LocalEnvironmentObservation(
            local.toLocalDate().toEpochDay(), local.dayOfWeek.value, local.hour, local.minute,
            local.zone.id, local.offset.totalSeconds,
        )
    } catch (_: Exception) {
        fail(NativeEnvironmentError.LOCAL_TIME_UNAVAILABLE)
    }

    private fun readCredentialStorage(): CredentialStorageState {
        val manager = try { application.getSystemService(UserManager::class.java) }
            catch (_: Exception) { fail(NativeEnvironmentError.CREDENTIAL_STORAGE_UNAVAILABLE) }
        if (manager == null) fail(NativeEnvironmentError.CREDENTIAL_STORAGE_UNAVAILABLE)
        val unlocked = try { manager.isUserUnlocked }
            catch (_: Exception) { fail(NativeEnvironmentError.CREDENTIAL_STORAGE_UNAVAILABLE) }
        return if (unlocked) CredentialStorageState.AVAILABLE else CredentialStorageState.LOCKED
    }

    private fun requireCredentialStorage() {
        if (readCredentialStorage() == CredentialStorageState.LOCKED) {
            fail(NativeEnvironmentError.CREDENTIAL_STORAGE_LOCKED)
        }
    }

    private fun readEntryIfPresent(file: File): BasicFileAttributes? = try {
        Files.readAttributes(file.toPath(), BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
    } catch (_: NoSuchFileException) {
        null
    }

    private fun requireDirectory(file: File) {
        val attributes = readEntryIfPresent(file) ?: fail(NativeEnvironmentError.DIRECTORY_UNAVAILABLE)
        val error = NativeEnvironmentRules.directoryEntryError(attributes.isDirectory, attributes.isSymbolicLink)
        if (error != null) fail(error)
    }

    override fun toString(): String = "NativeEnvironment(application_background_owner)"
}

private class EnvironmentFailure(val error: NativeEnvironmentError) :
    RuntimeException(null, null, false, false)

private fun fail(error: NativeEnvironmentError): Nothing = throw EnvironmentFailure(error)
