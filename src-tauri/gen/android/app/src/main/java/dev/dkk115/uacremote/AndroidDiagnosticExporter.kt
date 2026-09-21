// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote

import android.app.Activity
import android.content.ClipData
import android.content.ContentValues
import android.content.Intent
import android.content.Context
import android.net.Uri
import android.os.Environment
import android.os.Handler
import android.os.Looper
import android.provider.MediaStore
import dev.dkk115.uacremote.background.PolicyOwnerBounds
import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.util.concurrent.TimeUnit
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

internal enum class DiagnosticExportOutcome { SHARED, UNAVAILABLE }
internal enum class DiagnosticSaveOutcome { SAVED, CANCELLED, UNAVAILABLE }

/** Pure state table: one picker result and terminal reply. Retirement prevents
 * a new selection or a late success reply; an already-started provider IO may finish. */
internal class DiagnosticSaveOperationGate {
    private val completed = AtomicBoolean(false)
    private val selected = AtomicBoolean(false)
    fun select(): Boolean = !completed.get() && selected.compareAndSet(false, true)
    fun isOpen(): Boolean = !completed.get()
    fun finish(outcome: DiagnosticSaveOutcome): DiagnosticSaveOutcome? =
        if (completed.compareAndSet(false, true)) outcome else null
}

/** Pure terminal table for timeout/handoff races. Completion itself always runs
 * on the main thread; atomic identity keeps the invariant explicit in tests. */
internal class DiagnosticExportOperationGate {
    internal data class Handoff(
        val outcome: DiagnosticExportOutcome?,
        val deleteDocument: Boolean,
    )

    private val completed = AtomicBoolean(false)

    fun timeout(): DiagnosticExportOutcome? =
        if (completed.compareAndSet(false, true)) DiagnosticExportOutcome.UNAVAILABLE else null

    fun handoff(
        documentReady: Boolean,
        foreground: Boolean,
        launchShare: () -> Boolean,
    ): Handoff {
        if (!completed.compareAndSet(false, true)) return Handoff(null, documentReady)
        if (!documentReady || !foreground) {
            return Handoff(DiagnosticExportOutcome.UNAVAILABLE, documentReady)
        }
        val shared = try { launchShare() } catch (_: Exception) { false }
        return Handoff(
            if (shared) DiagnosticExportOutcome.SHARED else DiagnosticExportOutcome.UNAVAILABLE,
            deleteDocument = !shared,
        )
    }
}

/** Explicit foreground export only. Saves a user-owned Downloads document and
 * grants a receiver temporary read access through Android's Sharesheet. */
internal object AndroidDiagnosticExporter {
    private const val EXPORT_DIRECTORY = "UAC Remote Approval"
    private const val MAX_NATIVE_BYTES = 64 * 1024
    private const val MAX_EXPORT_BYTES = 384 * 1024
    private val fileTime = DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss").withZone(ZoneOffset.UTC)
    private val active = AtomicReference<Lease?>(null)
    @Volatile private var unreapedLogcat: java.lang.Process? = null
    private val worker = ThreadPoolExecutor(1, 1, 0, TimeUnit.MILLISECONDS, ArrayBlockingQueue<Runnable>(1),
        { work -> Thread(work, "uac-diagnostic-export").apply { isDaemon = true } }, ThreadPoolExecutor.AbortPolicy())

    private class Lease {
        fun release() { active.compareAndSet(this, null) }
    }
    private fun acquire(): Lease? {
        val lease = Lease()
        if (!active.compareAndSet(null, lease)) return null
        // Check after acquiring: a previous worker may have published its
        // unreaped-child obligation immediately before releasing its lease.
        if (unreapedLogcat?.isAlive == true) { lease.release(); return null }
        unreapedLogcat = null
        return lease
    }
    private fun execute(work: () -> Unit): Boolean = try { worker.execute { work() }; true } catch (_: Exception) { false }

    private data class Exported(val uri: Uri, val name: String)

    /** The picker is native-only; the renderer cannot supply a URI or contents.
     * Retiring an Activity cancels its pending selection. A started provider write
     * retains the global lease until it returns, even after its bounded UI timeout. */
    internal class SaveOperation internal constructor(
        private val context: Context,
        private val release: () -> Unit,
        private val completion: (DiagnosticSaveOutcome) -> Unit,
    ) {
        private val gate = DiagnosticSaveOperationGate()
        private val main = Handler(Looper.getMainLooper())
        private var writing = false
        private val timeout = Runnable { complete(DiagnosticSaveOutcome.UNAVAILABLE) }

        private fun complete(outcome: DiagnosticSaveOutcome) {
            val terminal = gate.finish(outcome) ?: return
            main.removeCallbacks(timeout)
            try { completion(terminal) } catch (_: Exception) { }
        }

        fun retire() {
            complete(DiagnosticSaveOutcome.UNAVAILABLE)
            if (!writing) release()
        }

        fun selected(uri: Uri?, cancelled: Boolean) {
            if (!gate.select()) return
            if (cancelled || uri?.scheme != "content") {
                complete(if (cancelled) DiagnosticSaveOutcome.CANCELLED else DiagnosticSaveOutcome.UNAVAILABLE)
                release()
                return
            }
            // URI is from ACTION_CREATE_DOCUMENT's result, never from JS. No
            // persistent grant or broad storage permission is requested.
            writing = true
            if (!main.postDelayed(timeout, PolicyOwnerBounds.RESPONSE_TIMEOUT_MILLIS) || !execute {
                val saved = try {
                    val bytes = snapshotBytes()
                    if (bytes == null || !gate.isOpen()) false
                    else context.contentResolver.openOutputStream(uri, "wt")?.use { output ->
                        output.write(bytes)
                        output.flush()
                        true
                    } ?: false
                } catch (_: Exception) { false }
                finally { release() }
                main.post { complete(if (saved) DiagnosticSaveOutcome.SAVED else DiagnosticSaveOutcome.UNAVAILABLE) }
            }) {
                writing = false
                release()
                complete(DiagnosticSaveOutcome.UNAVAILABLE)
            }
        }
    }

    fun beginSave(
        activity: Activity,
        stillForeground: () -> Boolean,
        completion: (DiagnosticSaveOutcome) -> Unit,
    ): SaveOperation? {
        if (Looper.myLooper() != Looper.getMainLooper() || !foreground(stillForeground)) return null
        val lease = acquire() ?: return null
        return SaveOperation(activity.applicationContext, lease::release, completion)
    }

    fun saveDocumentIntent(): Intent = Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
        addCategory(Intent.CATEGORY_OPENABLE)
        type = "text/plain"
        putExtra(Intent.EXTRA_TITLE, diagnosticName(System.currentTimeMillis()))
    }

    private fun diagnosticName(now: Long): String =
        "uac-remote-diagnostics-${fileTime.format(Instant.ofEpochMilli(now))}.txt"

    private fun snapshotBytes(now: Long = System.currentTimeMillis()): ByteArray? = render(
        now, BuildConfig.VERSION_NAME, AndroidDiagnosticStore.snapshot(), nativeLogSnapshot(),
    )

    /**
     * The single production Interface for the complete export operation.
     * False means no work was accepted and completion will not run. Once true
     * is returned, completion runs exactly once on Android's main thread with a
     * closed outcome. The global lease remains held through worker cleanup.
     */
    fun begin(
        activity: Activity,
        stillForeground: () -> Boolean,
        completion: (DiagnosticExportOutcome) -> Unit,
    ): Boolean {
        if (Looper.myLooper() != Looper.getMainLooper() || !foreground(stillForeground)) return false
        val main = Handler(Looper.getMainLooper())
        val lease = acquire() ?: return false
        val gate = DiagnosticExportOperationGate()
        val context = activity.applicationContext
        fun complete(outcome: DiagnosticExportOutcome) {
            try { completion(outcome) } catch (_: Exception) { }
        }
        val timeout = Runnable { gate.timeout()?.let(::complete) }
        if (!main.postDelayed(timeout, PolicyOwnerBounds.RESPONSE_TIMEOUT_MILLIS)) {
            lease.release()
            return false
        }
        if (!execute {
            val exported = try { create(context) } catch (_: Exception) { null }
            val posted = main.post {
                val handoff = gate.handoff(
                    documentReady = exported != null,
                    foreground = foreground(stillForeground),
                    launchShare = { exported != null && share(activity, exported) },
                )
                handoff.outcome?.let { outcome ->
                    main.removeCallbacks(timeout)
                    complete(outcome)
                }
                // FIFO cleanup cannot begin until the creation worker returns.
                // A real deletion obligation retains the lease if scheduling
                // fails, preventing repeated exports from accumulating files.
                val queued = execute {
                    try {
                        if (handoff.deleteDocument && exported != null) discard(context, exported)
                    } finally {
                        lease.release()
                    }
                }
                if (!queued && !handoff.deleteDocument) lease.release()
            }
            if (!posted) {
                // The already-scheduled main-thread timeout owns completion.
                try { if (exported != null) discard(context, exported) }
                finally { lease.release() }
            }
        }) {
            main.removeCallbacks(timeout)
            lease.release()
            return false
        }
        return true
    }

    private fun foreground(observe: () -> Boolean): Boolean = try { observe() } catch (_: Exception) { false }

    private fun create(activity: Context): Exported? {
        val now = System.currentTimeMillis()
        val bytes = snapshotBytes(now) ?: return null
        val name = diagnosticName(now)
        val values = ContentValues().apply {
            put(MediaStore.MediaColumns.DISPLAY_NAME, name)
            put(MediaStore.MediaColumns.MIME_TYPE, "text/plain")
            put(MediaStore.MediaColumns.RELATIVE_PATH, "${Environment.DIRECTORY_DOWNLOADS}/$EXPORT_DIRECTORY")
            put(MediaStore.MediaColumns.IS_PENDING, 1)
        }
        val resolver = activity.contentResolver
        val uri = try { resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values) }
        catch (_: Exception) { null } ?: return null
        try {
            resolver.openOutputStream(uri, "w")?.use { output -> output.write(bytes) } ?: error("output unavailable")
            values.clear(); values.put(MediaStore.MediaColumns.IS_PENDING, 0)
            if (resolver.update(uri, values, null, null) != 1) error("publish unavailable")
        } catch (_: Exception) {
            try { resolver.delete(uri, null, null) } catch (_: Exception) { }
            return null
        }
        return Exported(uri, name)
    }

    private fun share(activity: Activity, exported: Exported): Boolean = try {
        val send = Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_STREAM, exported.uri)
            putExtra(Intent.EXTRA_TITLE, exported.name)
            clipData = ClipData.newRawUri(exported.name, exported.uri)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        activity.startActivity(Intent.createChooser(send, activity.getString(R.string.app_name)))
        true
    } catch (_: Exception) { false }

    private fun discard(activity: Context, exported: Exported) {
        try { activity.contentResolver.delete(exported.uri, null, null) } catch (_: Exception) { }
    }

    internal fun render(
        unixMillis: Long,
        version: String,
        persisted: List<String>,
        native: List<String>?,
    ): ByteArray? {
        if (unixMillis < 0 || !token(version, 64)) return null
        val text = StringBuilder()
        fun append(line: String): Boolean {
            if (text.length + line.length + 1 > MAX_EXPORT_BYTES) return false
            text.append(line).append('\n'); return true
        }
        append("UAC_REMOTE_ANDROID_DIAGNOSTICS_V1")
        append("generated_unix_millis=$unixMillis")
        append("version=$version")
        append("scope=closed_diagnostic_tokens_no_request_bodies_keys_or_credentials")
        append("[persisted]")
        for (line in persisted) if (AndroidDiagnosticStore.validStoredRecord(line) && !append(line)) return null
        if (!append("[native_log_buffer]")) return null
        if (native == null) { if (!append("status=unavailable")) return null }
        else for (line in native) if (validNativeLine(line) && !append(line)) return null
        val bytes = text.toString().toByteArray(StandardCharsets.UTF_8)
        return bytes.takeIf { it.size in 1..MAX_EXPORT_BYTES }
    }

    private fun nativeLogSnapshot(): List<String>? {
        val process = try {
            ProcessBuilder(
                "/system/bin/logcat", "-d", "-v", "threadtime", "-t", "128",
                "--uid=${android.os.Process.myUid()}",
                "UacNative:I", "*:S",
            ).redirectErrorStream(true).start()
        } catch (_: Exception) { return null }
        return try {
            if (!process.waitFor(1800, TimeUnit.MILLISECONDS)) return null
            if (process.exitValue() != 0) return null
            val sink = ByteArrayOutputStream(MAX_NATIVE_BYTES + 1)
            val buffer = ByteArray(4096)
            process.inputStream.use { input ->
                while (sink.size() <= MAX_NATIVE_BYTES) {
                    val read = input.read(buffer, 0, minOf(buffer.size, MAX_NATIVE_BYTES + 1 - sink.size()))
                    if (read < 0) break
                    sink.write(buffer, 0, read)
                }
            }
            if (sink.size() > MAX_NATIVE_BYTES) null
            else sink.toString(StandardCharsets.UTF_8.name()).lineSequence().filter(::validNativeLine).take(128).toList()
        } catch (_: Exception) { null }
        finally {
            try {
                if (process.isAlive) {
                    process.destroyForcibly()
                    process.waitFor(200, TimeUnit.MILLISECONDS)
                }
            } catch (_: Exception) { }
            finally {
                // A stuck owned child prevents another export process until it
                // really exits; rotation/timeouts cannot accumulate processes.
                if (process.isAlive) unreapedLogcat = process
                for (stream in listOf<java.io.Closeable>(process.inputStream, process.errorStream, process.outputStream)) {
                    try { stream.close() } catch (_: Exception) { }
                }
            }
        }
    }

    private val threadtime = Regex("((?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])) (?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]\\.[0-9]{3} +([0-9]{1,10}) +([0-9]{1,10}) [VDIWEF] UacNative: (.+)")
    internal fun validNativeLine(line: String): Boolean {
        if (line.isEmpty() || line.length > 768 || !line.all { it.code in 0x20..0x7e }) return false
        val matched = threadtime.matchEntire(line) ?: return false
        return matched.groupValues[2].toIntOrNull()?.let { it > 0 } == true &&
            matched.groupValues[3].toIntOrNull()?.let { it > 0 } == true &&
            AndroidDiagnosticStore.validNativePayload(matched.groupValues[4])
    }

    private fun token(value: String, max: Int): Boolean =
        value.isNotEmpty() && value.length <= max &&
            value.all { it.isLetterOrDigit() && it.code < 128 || it in ".-_" }
}
