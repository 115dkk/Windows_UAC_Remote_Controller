// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.background

import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.NoSuchFileException
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.BasicFileAttributes
import java.util.concurrent.atomic.AtomicBoolean

/** Boot eligibility only: never a key, pairing, notification-policy or approval store. */
internal enum class BootActivationRecord { MISSING, ON, OFF, UNAVAILABLE }
internal enum class BootRegistrationOperation { START, STOP }
internal enum class BootRegistrationFailure { STORAGE, COMPONENT, CANCELLED }
internal data class BootRegistrationResult(val state: BootActivationState, val failure: BootRegistrationFailure? = null)

/** Downward native work is attempted before submitting persistence. Its failure
 * cannot be overwritten by a later successful OFF write (or vice versa). */
internal class BootStopCompletion private constructor(private val observation: NativeStopObservation?) {
    companion object {
        fun attempt(downward: () -> NativeStopObservation): BootStopCompletion =
            BootStopCompletion(try { downward() } catch (_: Exception) { null })
    }
    fun finish(result: BootRegistrationResult, started: Long, now: Long): ServiceControlResult =
        if (observation != null && result.failure == null && result.state == BootActivationState.OFF &&
            !BootServicePolicy.serviceCommandExpired(started, now)) ServiceControlResult.REQUESTED else ServiceControlResult.UNAVAILABLE
}

internal interface BootActivationStore {
    fun read(): BootActivationRecord
    fun commit(expected: BootActivationRecord, desired: BootActivationRecord, beforeWrite: () -> Boolean): Boolean
}

/** Fixed, bounded private record. The production directory is DE/no-backup and
 * obtained only on its sole worker. An unfinished replacement is UNKNOWN, not
 * absence/default-ON. No automatic recovery overwrites corrupt/partial data.
 * File/directory sync and readback are checked; hardware power-loss guarantees
 * are outside this API. The injected directory sync is native in production. */
internal class BootActivationFile(private val directory: File, private val syncDirectory: (File) -> Unit) : BootActivationStore {
    private val record = File(directory, "controller-boot-activation-v1")
    private val pending = File(directory, "controller-boot-activation-v1.pending")

    private fun attributes(file: File): BasicFileAttributes? = try {
        Files.readAttributes(file.toPath(), BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
    } catch (_: NoSuchFileException) { null }

    override fun read(): BootActivationRecord = try {
        if (attributes(directory)?.isDirectory != true || attributes(pending) != null) BootActivationRecord.UNAVAILABLE
        else {
            val found = attributes(record)
            if (found == null) BootActivationRecord.MISSING
            else if (!found.isRegularFile || found.size() !in 6L..7L) BootActivationRecord.UNAVAILABLE
            else FileInputStream(record).use { stream ->
                val bytes = ByteArray(8)
                var count = 0
                while (count < bytes.size) {
                    val read = stream.read(bytes, count, bytes.size - count)
                    if (read < 0) break
                    if (read == 0) throw IOException("Activation read made no progress")
                    count += read
                }
                when {
                    count == 6 && bytes.copyOf(count).contentEquals("v1:on\n".toByteArray(Charsets.US_ASCII)) -> BootActivationRecord.ON
                    count == 7 && bytes.copyOf(count).contentEquals("v1:off\n".toByteArray(Charsets.US_ASCII)) -> BootActivationRecord.OFF
                    else -> BootActivationRecord.UNAVAILABLE
                }
            }
        }
    } catch (_: Exception) { BootActivationRecord.UNAVAILABLE }

    override fun commit(expected: BootActivationRecord, desired: BootActivationRecord, beforeWrite: () -> Boolean): Boolean {
        if (expected == BootActivationRecord.UNAVAILABLE || desired !in setOf(BootActivationRecord.ON, BootActivationRecord.OFF)) return false
        return try {
            // The read itself may be delayed. Fence the first mutation after
            // that real read, using the caller's original ticket/deadline.
            if (read() != expected || !beforeWrite()) false
            else if (expected == desired) {
                // A previous rename may have become visible before directory
                // sync failed. Same-state retries must establish native sync,
                // not convert a readable value into a claimed durable receipt.
                FileChannel.open(record.toPath(), StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS).use { it.force(true) }
                syncDirectory(directory)
                read() == desired
            }
            else {
                // CREATE_NEW and retained partial files prevent overwriting an
                // uncertain prior operation; this directory has one app owner.
                Files.createFile(pending.toPath())
                FileOutputStream(pending).use { stream ->
                    stream.write((if (desired == BootActivationRecord.ON) "v1:on\n" else "v1:off\n").toByteArray(Charsets.US_ASCII))
                    stream.fd.sync()
                }
                syncDirectory(directory)
                Files.move(pending.toPath(), record.toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
                syncDirectory(directory)
                read() == desired
            }
        } catch (_: Exception) { false } // Preserve partial/committed state; never claim rollback.
    }
}

/** Pure worker-side composition. No arbitrary path/command or caller boolean
 * authorizes a start. The cancellation predicate belongs to its private ticket. */
internal class BootRegistrationIo(
    private val store: BootActivationStore,
    private val legacyComponent: () -> BootComponentState,
    private val wakeComponent: () -> BootComponentState,
) {
    fun initialize(mayContinue: () -> Boolean): BootRegistrationResult {
        val stored = store.read()
        val resolved = when (stored) {
            BootActivationRecord.ON -> BootActivationState.ON
            BootActivationRecord.OFF -> BootActivationState.OFF
            BootActivationRecord.UNAVAILABLE -> BootActivationState.UNAVAILABLE
            BootActivationRecord.MISSING -> when (legacyComponent()) {
                BootComponentState.DEFAULT -> migrate(BootActivationRecord.ON, mayContinue)
                BootComponentState.DISABLED -> migrate(BootActivationRecord.OFF, mayContinue)
                BootComponentState.ENABLED -> BootActivationState.LEGACY_MISSING
                BootComponentState.UNAVAILABLE -> BootActivationState.UNAVAILABLE
            }
        }
        return BootRegistrationResult(resolved,
            if (resolved == BootActivationState.UNAVAILABLE) BootRegistrationFailure.STORAGE else null)
    }

    private fun migrate(desired: BootActivationRecord, mayContinue: () -> Boolean): BootActivationState =
        if (!mayContinue() || !store.commit(BootActivationRecord.MISSING, desired, mayContinue)) BootActivationState.UNAVAILABLE
        else if (desired == BootActivationRecord.ON) BootActivationState.ON else BootActivationState.OFF

    fun mutate(expected: BootActivationState, operation: BootRegistrationOperation, mayContinue: () -> Boolean): BootRegistrationResult {
        val before = when (expected) {
            BootActivationState.ON -> BootActivationRecord.ON
            BootActivationState.OFF -> BootActivationRecord.OFF
            BootActivationState.LEGACY_MISSING -> BootActivationRecord.MISSING
            else -> return BootRegistrationResult(expected, BootRegistrationFailure.STORAGE)
        }
        val desired = if (operation == BootRegistrationOperation.START) BootActivationRecord.ON else BootActivationRecord.OFF
        if (!mayContinue()) return BootRegistrationResult(expected, BootRegistrationFailure.CANCELLED)
        if (!store.commit(before, desired, mayContinue)) return BootRegistrationResult(observed(), BootRegistrationFailure.STORAGE)
        // Commit may have completed after cancellation. Report the actual state,
        // but never turn that into permission for a delayed FGS continuation.
        val state = if (desired == BootActivationRecord.ON) BootActivationState.ON else BootActivationState.OFF
        if (!mayContinue()) return BootRegistrationResult(state, BootRegistrationFailure.CANCELLED)
        if (!BootServicePolicy.bootEnabled(wakeComponent())) return BootRegistrationResult(state, BootRegistrationFailure.COMPONENT)
        return BootRegistrationResult(state)
    }

    private fun observed(): BootActivationState = when (store.read()) {
        BootActivationRecord.ON -> BootActivationState.ON
        BootActivationRecord.OFF -> BootActivationState.OFF
        else -> BootActivationState.UNAVAILABLE
    }
}

/** One app-wide slot. Cancellation revokes continuation, not an entered disk
 * operation. Only actual worker completion releases the exact original ticket. */
internal class BootRegistrationFence(initialNext: Long = 1L) {
    internal class Ticket(val operation: BootRegistrationOperation, val started: Long, val generation: Long) {
        private val cancelled = AtomicBoolean(false)
        fun cancel() { cancelled.set(true) }
        fun mayContinue(now: Long): Boolean = !cancelled.get() && !BootServicePolicy.serviceCommandExpired(started, now)
    }
    private var next: Long? = initialNext.also { require(it > 0) }
    @Volatile var current: Ticket? = null
        private set
    fun reserve(operation: BootRegistrationOperation, started: Long): Ticket? {
        if (current != null) return null
        val value = next ?: return null
        next = if (value == Long.MAX_VALUE) null else value + 1L
        return Ticket(operation, started, value).also { current = it }
    }
    fun cancelStart() { current?.takeIf { it.operation == BootRegistrationOperation.START }?.cancel() }
    fun complete(ticket: Ticket): Boolean {
        if (current !== ticket) return false
        current = null
        return true
    }
}
