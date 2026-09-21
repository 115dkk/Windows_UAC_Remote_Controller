// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote

import android.app.Application
import android.util.Log
import android.os.Process
import android.system.Os
import android.system.OsConstants
import dev.dkk115.uacremote.background.*
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.nio.charset.StandardCharsets
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit

/**
 * Private, bounded persistence for the same closed diagnostic tokens that are
 * sent to logcat. This is not activity history or authorization state. It never
 * reads requests, identities, keys, exception messages or arbitrary caller text.
 *
 * The device-protected no-backup directory is available to the boot service
 * before first unlock and remains private to this app. Export is a separate,
 * explicit foreground action owned by [AndroidDiagnosticExporter].
 */
internal object AndroidDiagnosticStore {
    private const val DIRECTORY = "uac-diagnostics"
    private const val CURRENT = "current.log"
    private const val PREVIOUS = "previous.log"
    internal const val MAX_FILE_BYTES = 128 * 1024L
    internal const val MAX_LINE_CHARS = 384
    private const val MAX_STORED_LINE_CHARS = 512
    private val logcatTags = setOf("UacBoot", "UacNative", "UacScan")
    private val persistedTags = setOf("UacBoot", "UacNative")
    private val bootKeys = setOf(
        "stage", "action", "component", "unlock", "result", "failure", "admitted", "sticky",
        "generation_present", "attached", "promoted", "kept_current", "activation",
        "activation_pending", "activation_uncertain", "depth", "kind", "reason", "site",
        "symbol", "owner_step", "owner_phase", "owner_origin", "owner_category",
        "owner_status", "pinned",
    )
    private val token = Regex("[A-Za-z0-9_.$<>:|\\-]+")
    private val bootStages = BootDiagnosticStage.values().map { it.name }.toSet()
    private val ownerStages = OwnerDiagnosticEvent.values().map { it.name }.toSet()
    private val bootValues = mapOf(
        "action" to BootDiagnosticAction.values().map { it.name }.toSet(),
        "component" to BootComponentState.values().map { it.name }.toSet(),
        "unlock" to UserUnlockObservation.values().map { it.name }.toSet(),
        "result" to ServiceControlResult.values().map { it.name }.toSet(),
        "failure" to BootDiagnosticFailure.values().map { it.name }.toSet(),
        "activation" to BootActivationState.values().map { it.name }.toSet(),
        "owner_step" to OwnerInitializationStep.values().map { it.name }.toSet(),
        "owner_phase" to PolicyOwnerPhase.values().map { it.name }.toSet(),
        "owner_origin" to OwnerFailureOrigin.values().map { it.name }.toSet(),
        "owner_category" to OwnerFailureCategory.values().map { it.name }.toSet(),
        "owner_status" to PolicyStatus.values().map { it.name }.toSet(),
    )
    private val booleans = setOf("admitted", "sticky", "generation_present", "attached", "promoted", "kept_current", "activation_pending", "activation_uncertain")
    private val errors = setOf("NONE", "LIFECYCLE_INTEGRATION_REQUIRED", "OWNER_FAULTED", "NATIVE_UNAVAILABLE", "INVALID_OBSERVATION", "BUSY", "STORAGE_UNAVAILABLE", "INVALID_POLICY", "CLOSED", "HISTORY_TIME_UNAVAILABLE", "LOCAL_KEYS_RECONCILIATION_REQUIRED", "LOCAL_KEYS_UNAVAILABLE", "APPROVAL_REJECTED", "DENIAL_REJECTED", "REQUEST_UNAVAILABLE", "PRESENTATION_REFRESH_REQUIRED")
    private val intakeSites = setOf("RUNTIME_JOIN", "REACTOR", "MAINTENANCE", "PRESENTATION_PAUSE", "PEER_WORK", "NATIVE_PROGRESS", "DIAL_JOIN", "PEER_JOIN", "PEER_BUDGET", "CLOCK")
    private val steps = setOf("ATTACH_SOCKET", "READY_PROBE", "MESSAGE_CLOCK", "MESSAGE_APPLY", "MESSAGE_PROBE", "MESSAGE_EFFECTS", "DECISION_DELIVER", "EFFECT_PRUNE", "EFFECT_WITHDRAW", "EFFECT_RECONCILE", "EFFECT_PUBLISH", "EFFECT_DEADLINE")
    private val startupReasons = setOf(
        "BOOTSTRAP_TOO_MANY_ENTRIES", "BOOTSTRAP_NON_UNICODE_ENTRY", "BOOTSTRAP_UNKNOWN_ENTRY", "BOOTSTRAP_EXISTING_KEYS", "BOOTSTRAP_LEGACY_POLICY", "BOOTSTRAP_MARKER_LENGTH", "BOOTSTRAP_MARKER_CONTENTS", "BOOTSTRAP_UNSAFE_FILE", "BOOTSTRAP_LINK_COUNT", "BOOTSTRAP_REPARSE_POINT", "BOOTSTRAP_IO_PERMISSION_DENIED", "BOOTSTRAP_IO_NOT_FOUND", "BOOTSTRAP_IO_ALREADY_EXISTS", "BOOTSTRAP_IO_OTHER",
        "RESOLVED_INTERRUPTED_COMMIT", "RESOLVED_ABANDONED_PREPARATIONS",
        "STORE_DIRECTORY_UNAVAILABLE", "STORE_UNSUPPORTED_PLATFORM", "STORE_UNSAFE_ENTRY", "STORE_STATE_ALREADY_EXISTS", "STORE_MISSING_STATE", "STORE_WRITER_LOCKED", "STORE_RECOVERY_REQUIRED", "STORE_INTERRUPTED_COMMIT", "STORE_CORRUPT_SNAPSHOT", "STORE_UNSUPPORTED_VERSION", "STORE_SNAPSHOT_TOO_LARGE", "STORE_EXTERNAL_CHANGE", "STORE_READ_FAILED", "STORE_WRITE_FAILED", "STORE_COMMIT_UNCERTAIN", "STORE_POISONED", "STORE_GENERATION_EXHAUSTED",
        "COMPOSITE_INVALID_ENCODING", "COMPOSITE_UNSUPPORTED_VERSION", "COMPOSITE_TOO_LARGE", "COMPOSITE_LEGACY_HISTORY", "COMPOSITE_HISTORY_PROFILE", "COMPOSITE_RECORDED_PENDING_OVERLAP", "COMPOSITE_HISTORY", "COMPOSITE_LOCAL_KEYS", "COMPOSITE_PEER_ASSOCIATIONS", "COMPOSITE_RECEIVING_SOURCE", "COMPOSITE_ROUTING_CANDIDATES",
        "DURABLE_HISTORY", "DURABLE_LIFECYCLE_INTEGRATION", "DURABLE_LOCAL_KEY_RECONCILIATION", "DURABLE_NATIVE_LOCAL_KEYS", "DURABLE_LOCAL_KEYS", "DURABLE_DIRECTORY_SYNCHRONIZATION", "DURABLE_TRANSITION_INCOMPLETE",
        "CHECKPOINT_INVALID_BOOT", "CHECKPOINT_MISSING_BOOT", "CHECKPOINT_CLOCK_REGRESSED", "CHECKPOINT_INVALID_STATE", "CHECKPOINT_UNSUPPORTED_VERSION", "CHECKPOINT_TOO_LARGE", "CHECKPOINT_LEGACY_OUTCOME", "CHECKPOINT_OUTCOME_RETENTION",
    )
    private val measurementNames = mapOf("APPROVAL_EXPIRED_ON_WORKER" to "phase", "APPROVAL_CLEANUP_REFUSED" to "reason", "APPROVAL_CLEANUP_COMPLETE" to "admission_waits", "APPROVAL_RETIRE_BUSY" to "waits", "APPROVAL_CLEANUP_WAKE" to "posted", "NOTIFICATION_REMAINING" to "millis")
    private val throwSites = setOf("INTAKE_PROGRESS", "PRESENTATION_CLOCK", "PUBLISH_PENDING_REQUEST", "WITHDRAW_REQUESTS", "CLOCK", "REGISTRY_PUBLISH_CAUSE", "APPROVAL_CLOSE_SUBMISSION", "APPROVAL_RETIRE", "APPROVAL_CLOSE_ATTEMPT", "APPROVAL_CLOSE_PLAN", "APPROVAL_CLEANUP_COMPLETE")
    private val nativePatterns = listOf(
        Regex("UAC_NATIVE_DECISION_V1 sample=[0-9]+ action=(?:approve|deny) outcome=(?:approved|denied|failed|cancelled|expired|expired_locally|pc_completed) timing_eligible=(?:true|false) action_to_receipt_ms=[0-9]+ action_to_auth_ms=(?:none|[0-9]+) auth_to_receipt_ms=(?:none|[0-9]+) local_ready_to_receipt_ms=(?:none|[0-9]+)"),
        Regex("UAC_NATIVE_INTAKE_V1 site=[A-Z0-9_]+ error=[A-Z0-9_]+"),
        Regex("UAC_NATIVE_STEP_V1 step=[A-Z0-9_]+ error=[A-Z0-9_]+"),
        Regex("UAC_NATIVE_STARTUP_V1 stage=[A-Z0-9_]+ reason=[A-Z0-9_]+"),
        Regex("UAC_NATIVE_VALUE_V1 site=[A-Za-z0-9_$]+ name=[A-Za-z0-9_$]+ value=-?[0-9]+"),
        Regex("UAC_NATIVE_THROW_V1 site=[A-Za-z0-9_$]+ at=(?:unknown|[A-Za-z0-9_$.:|]+) kind=[A-Za-z0-9_$]+"),
        Regex("UAC_NATIVE_PANIC_V1 file=[A-Za-z0-9_./\\\\:$<>-]+ line=[0-9]+ column=[0-9]+ thread=[A-Za-z0-9_-]+"),
    )
    private val lock = Any()
    // Logging never waits for filesystem IO on an auth/service/main thread.
    private val writer = ThreadPoolExecutor(1, 1, 0, TimeUnit.MILLISECONDS, ArrayBlockingQueue<Runnable>(64),
        { work -> Thread(work, "uac-diagnostic-store").apply { isDaemon = true } }, ThreadPoolExecutor.AbortPolicy())
    @Volatile private var directory: File? = null

    fun initialize(application: Application) {
        try {
            val root = application.createDeviceProtectedStorageContext().noBackupFilesDir.canonicalFile
            val candidate = File(root, DIRECTORY)
            if (candidate.canonicalFile != candidate || (!candidate.exists() && !candidate.mkdir()) ||
                !OsConstants.S_ISDIR(Os.lstat(candidate.path).st_mode) || Os.lstat(candidate.path).st_uid != Process.myUid()) return
            synchronized(lock) { directory = candidate }
        } catch (_: Exception) {
            // Diagnostics never change boot admission or service ownership.
        }
    }

    /** Emits to logcat for developer tooling and, independently, to private storage. */
    fun record(tag: String, line: String) {
        if (!logcatAdmissible(tag, line)) return
        try { Log.i(tag, line) } catch (_: Throwable) { }
        // Scanner lines remain developer-only: some fields originate at the
        // renderer command boundary and are not part of the export contract.
        if (!persistable(tag, line)) return
        val record = storedRecord(System.currentTimeMillis(), tag, line) ?: return
        try {
            writer.execute {
                try { synchronized(lock) {
                    val root = directory ?: return@synchronized
                    append(root, record.toByteArray(StandardCharsets.US_ASCII))
                } } catch (_: Exception) { /* Best-effort private diagnostics only. */ }
            }
        } catch (_: Exception) {
            // A full/unavailable diagnostic store cannot affect the product.
        }
    }

    /** Immutable bounded snapshot; invalid/corrupt lines are omitted, never widened. */
    fun snapshot(): List<String> = try {
        synchronized(lock) {
            val root = directory ?: return emptyList()
            buildList {
                addAll(readValidated(File(root, PREVIOUS)))
                addAll(readValidated(File(root, CURRENT)))
            }
        }
    } catch (_: Exception) { emptyList() }

    internal fun persistable(tag: String, line: String): Boolean =
        tag in persistedTags && logcatAdmissible(tag, line) && when (tag) {
            "UacBoot" -> validBootPayload(line)
            "UacNative" -> validNativePayload(line)
            else -> false
        }

    internal fun storedRecord(unixMillis: Long, tag: String, line: String): String? {
        if (unixMillis < 0 || !persistable(tag, line)) return null
        return "unix_millis=$unixMillis tag=$tag $line\n"
            .takeIf { it.length <= MAX_STORED_LINE_CHARS }
    }

    internal fun validStoredRecord(line: String): Boolean {
        if (line.isEmpty() || line.length > MAX_STORED_LINE_CHARS ||
            !line.all { it.code in 0x20..0x7e }) return false
        val prefix = "unix_millis="
        if (!line.startsWith(prefix)) return false
        val timeEnd = line.indexOf(' ', prefix.length)
        val unixMillis = if (timeEnd <= prefix.length) null else line.substring(prefix.length, timeEnd).toLongOrNull()
        if (unixMillis == null || unixMillis < 0) return false
        val tagPrefix = " tag="
        if (!line.startsWith(tagPrefix, timeEnd)) return false
        val tagEnd = line.indexOf(' ', timeEnd + tagPrefix.length)
        if (tagEnd <= timeEnd + tagPrefix.length) return false
        return persistable(line.substring(timeEnd + tagPrefix.length, tagEnd), line.substring(tagEnd + 1))
    }

    private fun append(root: File, bytes: ByteArray) {
        if (bytes.isEmpty() || bytes.size > MAX_STORED_LINE_CHARS) return
        val current = File(root, CURRENT)
        if (!safeLeaf(root, current) || (current.exists() && current.length() > MAX_FILE_BYTES)) return
        if (current.exists() && current.length() + bytes.size > MAX_FILE_BYTES) {
            val previous = File(root, PREVIOUS)
            if (!safeLeaf(root, previous)) return
            if (previous.exists() && !previous.delete()) return
            if (!current.renameTo(previous)) return
        }
        FileOutputStream(current, true).use { output -> output.write(bytes) }
    }

    private fun readValidated(file: File): List<String> {
        if (!safeLeaf(file.parentFile ?: return emptyList(), file) || !file.isFile || file.length() !in 1..MAX_FILE_BYTES) return emptyList()
        val bytes = ByteArray(MAX_FILE_BYTES.toInt() + 1)
        var count = 0
        FileInputStream(file).use { input ->
            while (count < bytes.size) { val n = input.read(bytes, count, bytes.size - count); if (n < 0) break; count += n }
        }
        if (count > MAX_FILE_BYTES) return emptyList()
        return String(bytes, 0, count, StandardCharsets.US_ASCII).lineSequence().filter(::validStoredRecord).toList()
    }

    // The private app UID is the trust boundary; no cross-UID attacker can race
    // these paths. Reject stale aliases/hardlinks rather than following them.
    private fun safeLeaf(root: File, file: File): Boolean {
        if (file.canonicalFile != file || file.parentFile != root) return false
        return try { val stat = Os.lstat(file.path); OsConstants.S_ISREG(stat.st_mode) && stat.st_uid == Process.myUid() && stat.st_nlink == 1L }
        catch (error: android.system.ErrnoException) { error.errno == OsConstants.ENOENT }
    }

    private fun logcatAdmissible(tag: String, line: String): Boolean =
        tag in logcatTags && line.isNotEmpty() && line.length <= MAX_LINE_CHARS &&
            line.all { it.code in 0x20..0x7e }

    internal fun validNativePayload(line: String): Boolean {
        if (!line.startsWith("UAC_NATIVE_") || line.length > MAX_LINE_CHARS || !nativePatterns.any { it.matches(line) }) return false
        val parts = line.split(' ')
        val fields = parts.drop(1).associate { it.substringBefore('=') to it.substringAfter('=') }
        return when (parts[0]) {
            "UAC_NATIVE_DECISION_V1" -> {
                val total = fields["action_to_receipt_ms"]?.toLongOrNull()
                val auth = fields["action_to_auth_ms"]?.toLongOrNull()
                val after = fields["auth_to_receipt_ms"]?.toLongOrNull()
                fields["sample"]?.toIntOrNull()?.let { it in 1..1_000_000 } == true &&
                    total != null && total in 0..300_000 &&
                    listOf("action_to_auth_ms", "auth_to_receipt_ms", "local_ready_to_receipt_ms").all { key ->
                        fields[key] == "none" || fields[key]?.toLongOrNull()?.let { it in 0..total } == true
                    } && (auth == null) == (after == null) &&
                    (auth == null || after != null && total - auth - after in 0..1) &&
                    (fields["action"] != "deny" || auth == null) &&
                    (if (fields["timing_eligible"] == "true") {
                        fields["local_ready_to_receipt_ms"] != "none" &&
                            ((fields["action"] == "approve" && fields["outcome"] == "approved" && auth != null) ||
                                (fields["action"] == "deny" && fields["outcome"] == "denied"))
                    } else auth == null)
            }
            "UAC_NATIVE_INTAKE_V1" -> fields["site"] in intakeSites && fields["error"] in errors
            "UAC_NATIVE_STEP_V1" -> fields["step"] in steps && fields["error"] in errors
            "UAC_NATIVE_STARTUP_V1" -> fields["stage"] in setOf("DIRECTORY", "BOOTSTRAP", "OPEN_EXISTING", "CREATE_FRESH") && fields["reason"] in startupReasons
            "UAC_NATIVE_VALUE_V1" -> measurementNames[fields["site"]] == fields["name"] && fields["value"]?.toLongOrNull() != null
            "UAC_NATIVE_THROW_V1" -> fields["site"] in throwSites && fields["kind"]!!.length <= 64 &&
                (fields["at"] == "unknown" || fields["at"]!!.split('|').let { frames -> frames.size <= 3 && frames.all { Regex("[A-Za-z0-9_$]{1,64}\\.[A-Za-z0-9_$]{1,64}:[0-9]{1,10}").matches(it) } })
            "UAC_NATIVE_PANIC_V1" -> fields["file"]!!.length <= 128 && fields["thread"]!!.length <= 32 && fields["line"]?.toUIntOrNull() != null && fields["column"]?.toUIntOrNull() != null
            else -> false
        }
    }

    private fun validBootPayload(line: String): Boolean {
        val fields = line.split(' ')
        if (fields.isEmpty() || fields.size > 20) return false
        val seen = HashSet<String>()
        for ((index, field) in fields.withIndex()) {
            val split = field.indexOf('=')
            if (split <= 0 || split == field.lastIndex) return false
            val key = field.substring(0, split)
            val value = field.substring(split + 1)
            if (key !in bootKeys || !seen.add(key) || !token.matches(value)) return false
            if (index == 0 && key != "stage") return false
        }
        val values = fields.associate { it.substringBefore('=') to it.substringAfter('=') }
        return when (values["stage"]) {
            in bootStages -> values.all { (key, value) -> key == "stage" ||
                key in booleans && value in setOf("true", "false") ||
                key in setOf("action", "component", "unlock", "result", "failure", "activation") && value in bootValues.getValue(key) }
            in ownerStages -> "owner_phase" in values && values.all { (key, value) -> key == "stage" || key.startsWith("owner_") && value in (bootValues[key] ?: emptySet()) }
            "CALLBACK_PIN" -> values.keys == setOf("stage", "pinned") && values["pinned"]?.toIntOrNull()?.let { it >= 0 } == true
            "CONTRACT_LINKAGE" -> values.keys == setOf("stage", "depth", "kind", "reason", "site", "symbol") &&
                values["depth"] in setOf("0", "1", "2", "3") &&
                values["kind"] in setOf("INITIALIZER", "UNSATISFIED_LINK", "CLASS_MISSING", "METHOD_MISSING", "FIELD_MISSING", "ARGUMENT", "STATE", "RUNTIME", "OTHER") &&
                values["reason"] in setOf("CONTRACT_VERSION", "API_CHECKSUM", "LIBRARY_LOAD", "SYMBOL_LOOKUP", "STRUCTURE", "NATIVE_VERSION", "OTHER") &&
                values["site"]!!.length <= 180 && (values["site"] == "unknown" || Regex("(?:com\\.sun\\.jna|dev\\.dkk115\\.uacremote\\.nativecore)\\.[A-Za-z0-9_.$<>-]+:-?[0-9]+").matches(values["site"]!!)) &&
                (values["symbol"] == "none" || values["symbol"]!!.length <= 80 && Regex("(?:ffi_|uniffi_)uac_android_controller_[A-Za-z0-9_]+").matches(values["symbol"]!!))
            else -> false
        }
    }
}
