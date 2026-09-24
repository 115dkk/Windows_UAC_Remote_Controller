// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote

import android.accessibilityservice.AccessibilityServiceInfo
import android.graphics.Bitmap
import android.os.Bundle
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import android.view.KeyEvent
import android.view.accessibility.AccessibilityNodeInfo
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.io.ByteArrayOutputStream
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.FutureTask
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

/** Real Android picker/provider plus production exporter on the disposable CI
 * AVD. This is native storage proof, not a physical-phone or JS-bridge claim. */
@RunWith(AndroidJUnit4::class)
class AndroidDiagnosticSaveInstrumentationTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val main = Handler(Looper.getMainLooper())

    private class Pending {
        val done = CountDownLatch(1)
        val outcome = AtomicReference<DiagnosticSaveOutcome?>(null)
        var operation: AndroidDiagnosticExporter.SaveOperation? = null
    }

    @Test fun documentPickerCancellationAndActualProviderSave() {
        val automation = instrumentation.uiAutomation
        val originalFlags = automation.serviceInfo.flags
        automation.serviceInfo = automation.serviceInfo.apply {
            flags = originalFlags or AccessibilityServiceInfo.FLAG_REPORT_VIEW_IDS
        }
        try {
            ActivityScenario.launch(MainActivity::class.java).use { scenario ->
                var activity: MainActivity? = null
                scenario.onActivity { activity = it }
                val host = requireNotNull(activity)
                await { onMain { foreground(host) } }
                val cancelled = launch(host)
                try {
                    await { pickerVisible() }
                    instrumentation.sendKeyDownUpSync(KeyEvent.KEYCODE_BACK)
                    assertTrue("Picker cancellation must complete", cancelled.done.await(15, TimeUnit.SECONDS))
                    assertEquals(DiagnosticSaveOutcome.CANCELLED, cancelled.outcome.get())
                } finally { retire(cancelled) }

                await { onMain { foreground(host) } }
                val saved = launch(host)
                try {
                    await { pickerVisible() }
                    capturePicker("picker-ready")
                    selectDownloadsRoot()
                    // The production intent supplies a fixed synthetic-friendly
                    // diagnostic name. Only change the selected filename in the
                    // actual OS UI, ensuring independent repeated CI runs.
                    val name = "uac-diagnostic-ci-${UUID.randomUUID()}.txt"
                    awaitAction(
                        "set the selected filename",
                        AccessibilityNodeInfo.ACTION_SET_TEXT,
                        Bundle().apply {
                            putCharSequence(AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE, name)
                        },
                    ) { it.isEditable && it.isEnabled }
                    val saveButton = { node: AccessibilityNodeInfo ->
                        node.viewIdResourceName?.endsWith(":id/button1") == true && node.isEnabled && node.isClickable
                    }
                    // Observe the save control before the capture so the
                    // evidence describes the state the click acts on.
                    awaitNode("observe the save control", saveButton)
                    capturePicker("before-save")
                    awaitAction("save the selected document", AccessibilityNodeInfo.ACTION_CLICK, match = saveButton)
                    assertTrue("Selected provider write must complete", saved.done.await(20, TimeUnit.SECONDS))
                    assertEquals(DiagnosticSaveOutcome.SAVED, saved.outcome.get())
                    // Read only the exact synthetic filename selected in the
                    // verified Downloads root, on the disposable CI emulator.
                    // No product URI getter or storage permission is added.
                    assertTrue(name.matches(Regex("uac-diagnostic-ci-[a-f0-9-]{36}\\.txt")))
                    val bytes = ParcelFileDescriptor.AutoCloseInputStream(
                        automation.executeShellCommand("head -c 393217 /sdcard/Download/$name"),
                    ).use { input ->
                        val result = java.io.ByteArrayOutputStream()
                        val buffer = ByteArray(4096)
                        while (result.size() <= 384 * 1024) {
                            val count = input.read(buffer)
                            if (count < 0) break
                            result.write(buffer, 0, count)
                        }
                        result.toByteArray()
                    }
                    assertTrue("Exact saved document must contain bounded bytes", bytes.size in 1..(384 * 1024))
                    val text = String(bytes, Charsets.UTF_8)
                    assertTrue(text.startsWith("UAC_REMOTE_ANDROID_DIAGNOSTICS_V1\n"))
                    assertTrue(text.contains("scope=closed_diagnostic_tokens_no_request_bodies_keys_or_credentials\n"))
                    assertTrue(text.contains("[persisted]\n"))
                    assertTrue(text.contains("[native_log_buffer]\n"))
                    // Keep the one small selected document in this disposable
                    // AVD; do not delete a user-selected storage target.
                } catch (failure: Throwable) {
                    capturePicker("picker-failure")
                    throw failure
                } finally { retire(saved) }
            }
        } finally {
            automation.serviceInfo = automation.serviceInfo.apply { flags = originalFlags }
        }
    }

    private fun launch(host: MainActivity): Pending = onMain {
        val pending = Pending()
        val operation = AndroidDiagnosticExporter.beginSave(
            host, { foreground(host) }, { !host.isDestroyed && !host.isFinishing },
        ) { result ->
            pending.outcome.set(result)
            pending.done.countDown()
        }
        assertNotNull("Production save must accept this current foreground Activity", operation)
        pending.operation = requireNotNull(operation)
        pending
    }

    private fun retire(pending: Pending) = onMain {
        pending.operation?.retire()
    }

    private fun selectDownloadsRoot() {
        // The guarded CI system image uses English system UI; app locale does
        // not change DocumentsUI. Observe the real drawer and selected root.
        awaitAction("open the roots drawer", AccessibilityNodeInfo.ACTION_CLICK) {
            it.contentDescription?.toString() in setOf("Show roots", "Show navigation drawer")
        }
        // The toolbar and breadcrumb also say Downloads while the drawer is
        // open. Only the observed root-list title belongs to the clickable row.
        awaitAction("select the Downloads root", AccessibilityNodeInfo.ACTION_CLICK) {
            it.viewIdResourceName == "android:id/title" && it.text?.toString() == "Downloads" && it.isEnabled
        }
        await {
            findNode { it.viewIdResourceName?.endsWith(":id/roots_list") == true && it.isVisibleToUser } == null &&
                findNode { it.text?.toString() == "Downloads" } != null &&
                findNode { it.viewIdResourceName?.endsWith(":id/button1") == true && it.isEnabled } != null
        }
    }

    /** One bounded attempt on a node the picker may already have replaced.
     * A stale node, a vanished clickable ancestor or a refused action means
     * "not this frame", never a verdict; the caller retries within its own
     * deadline. Ancestry stays bounded exactly as before. */
    private fun attempt(node: AccessibilityNodeInfo, action: Int, arguments: Bundle?): Boolean {
        if (!node.refresh()) return false
        if (action != AccessibilityNodeInfo.ACTION_CLICK) {
            return node.isEnabled && node.performAction(action, arguments)
        }
        var current: AccessibilityNodeInfo? = node
        repeat(8) {
            val candidate = current ?: return false
            if (candidate.isClickable && candidate.isEnabled) {
                return candidate.performAction(AccessibilityNodeInfo.ACTION_CLICK)
            }
            current = candidate.parent
        }
        return false
    }

    private fun foreground(host: MainActivity): Boolean = !host.isDestroyed && !host.isFinishing &&
        host.hasWindowFocus() && (host.application as ControllerApplication).isCurrentForegroundControllerHost(host)

    private fun pickerVisible(): Boolean =
        instrumentation.uiAutomation.rootInActiveWindow?.packageName?.toString()?.contains("documentsui") == true

    /** Optional diagnostic evidence, never a substitute for assertions. The
     * explicit disposable-AVD predicate and checked DocumentsUI root exclude
     * authentication, QR enrollment and application request presentation. */
    private fun capturePicker(stage: String) {
        if (stage !in setOf("picker-ready", "before-save", "picker-failure")) return
        if (InstrumentationRegistry.getArguments().getString("diagnosticCapture") != "uac-lifecycle-ci-36-x86_64" ||
            Build.VERSION.SDK_INT != 36 || Build.HARDWARE !in setOf("ranchu", "goldfish")) return
        val captureRun = InstrumentationRegistry.getArguments().getString("diagnosticCaptureRun") ?: return
        if (!captureRun.matches(Regex("[0-9]{13}"))) return
        try {
            val root = instrumentation.uiAutomation.rootInActiveWindow ?: return
            val expectedPackage = root.packageName?.toString() ?: return
            if (expectedPackage !in setOf("com.android.documentsui", "com.google.android.documentsui")) return
            val queue = ArrayDeque<AccessibilityNodeInfo>(); queue.add(root)
            val text = StringBuilder("UAC_DOCUMENT_PICKER_CI_V1\ncapture_run=$captureRun\nstage=$stage\npackage=$expectedPackage\n")
            fun field(value: CharSequence?): String = value?.toString()?.take(160)
                ?.map { if (it == '\n' || it == '\r' || it == '\t' || it.code < 0x20) ' ' else it }
                ?.joinToString("") ?: ""
            var count = 0
            while (queue.isNotEmpty() && count < 256 && text.length < 48 * 1024) {
                val node = queue.removeFirst()
                if (node.packageName?.toString() != expectedPackage) continue
                text.append("node=${count++} id=${field(node.viewIdResourceName)} class=${field(node.className)}")
                    .append(" enabled=${node.isEnabled} clickable=${node.isClickable} editable=${node.isEditable}")
                    .append(" text=${field(node.text)} description=${field(node.contentDescription)}\n")
                for (index in 0 until minOf(node.childCount, 256 - count - queue.size)) {
                    node.getChild(index)?.let(queue::add)
                }
            }
            text.append("remaining_nodes=${queue.size}\n")
            val directory = instrumentation.targetContext.getExternalFilesDir(null) ?: return
            File(directory, "diagnostic-save-$stage.txt").writeText(text.toString().take(64 * 1024), Charsets.UTF_8)
            if (instrumentation.uiAutomation.rootInActiveWindow?.packageName?.toString() != expectedPackage) return
            val bitmap = instrumentation.uiAutomation.takeScreenshot() ?: return
            try {
                // Recheck after capture: an intervening app transition must not
                // leave another app's pixels as DocumentsUI evidence.
                if (instrumentation.uiAutomation.rootInActiveWindow?.packageName?.toString() != expectedPackage ||
                    bitmap.width > 4096 || bitmap.height > 4096 ||
                    bitmap.width.toLong() * bitmap.height > 4_194_304L) return
                val image = ByteArrayOutputStream()
                if (bitmap.compress(Bitmap.CompressFormat.PNG, 100, image) && image.size() <= 4 * 1024 * 1024) {
                    File(directory, "diagnostic-save-$stage.png").writeBytes(image.toByteArray())
                    File(directory, "diagnostic-save-$stage.txt").appendText("screenshot=ready\n", Charsets.UTF_8)
                }
            } finally { bitmap.recycle() }
        } catch (_: Exception) {
            // Evidence capture must not replace or swallow the original failure.
            System.out.println("UAC_DOCUMENT_PICKER_CI_CAPTURE_UNAVAILABLE stage=$stage")
        }
    }

    private fun findNode(match: (AccessibilityNodeInfo) -> Boolean): AccessibilityNodeInfo? {
        val root = instrumentation.uiAutomation.rootInActiveWindow ?: return null
        if (root.packageName?.toString()?.contains("documentsui") != true) return null
        val queue = ArrayDeque<AccessibilityNodeInfo>(); queue.add(root)
        var count = 0
        while (queue.isNotEmpty()) {
            val node = queue.removeFirst()
            assertTrue("Bounded system-picker accessibility tree", ++count <= 256)
            if (match(node)) return node
            assertTrue(count + queue.size + node.childCount <= 256)
            for (index in 0 until node.childCount) node.getChild(index)?.let(queue::add)
        }
        return null
    }

    private fun <T> onMain(action: () -> T): T {
        val task = FutureTask<T> { action() }
        assertTrue(main.post(task))
        return try { task.get(5, TimeUnit.SECONDS) }
        catch (error: Exception) { task.cancel(false); throw AssertionError("Native save main operation failed", error) }
    }

    private fun await(condition: () -> Boolean) {
        val deadline = SystemClock.elapsedRealtime() + OBSERVATION_DEADLINE_MILLIS
        do { if (condition()) return; SystemClock.sleep(OBSERVATION_INTERVAL_MILLIS) } while (SystemClock.elapsedRealtime() < deadline)
        throw AssertionError("Native document-picker observation deadline")
    }

    /** Returns the node itself rather than proving that one existed a moment
     * ago. Polling for presence and then querying again reads the live
     * DocumentsUI tree twice, and the second read can land in a frame where
     * the node is absent; that produced the only observed CI failure. */
    private fun awaitNode(purpose: String, match: (AccessibilityNodeInfo) -> Boolean): AccessibilityNodeInfo {
        val deadline = SystemClock.elapsedRealtime() + OBSERVATION_DEADLINE_MILLIS
        do {
            findNode(match)?.let { return it }
            SystemClock.sleep(OBSERVATION_INTERVAL_MILLIS)
        } while (SystemClock.elapsedRealtime() < deadline)
        throw AssertionError("Native document-picker observation deadline: $purpose")
    }

    /** Finds and acts within one bounded operation, so no node crosses a
     * frame boundary between being observed and being used. A product
     * regression still fails loudly here, at the same deadline as before. */
    private fun awaitAction(
        purpose: String,
        action: Int,
        arguments: Bundle? = null,
        match: (AccessibilityNodeInfo) -> Boolean,
    ) {
        val deadline = SystemClock.elapsedRealtime() + OBSERVATION_DEADLINE_MILLIS
        do {
            val node = findNode(match)
            if (node != null && attempt(node, action, arguments)) return
            SystemClock.sleep(OBSERVATION_INTERVAL_MILLIS)
        } while (SystemClock.elapsedRealtime() < deadline)
        throw AssertionError("Native document-picker action deadline: $purpose")
    }

    private companion object {
        const val OBSERVATION_DEADLINE_MILLIS = 30_000L
        const val OBSERVATION_INTERVAL_MILLIS = 50L
    }
}
