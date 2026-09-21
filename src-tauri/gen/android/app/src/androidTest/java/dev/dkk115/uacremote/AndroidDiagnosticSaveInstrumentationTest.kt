// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote

import android.accessibilityservice.AccessibilityServiceInfo
import android.os.Bundle
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
                    selectDownloadsRoot()
                    // The production intent supplies a fixed synthetic-friendly
                    // diagnostic name. Only change the selected filename in the
                    // actual OS UI, ensuring independent repeated CI runs.
                    val name = "uac-diagnostic-ci-${UUID.randomUUID()}.txt"
                    await { findNode { it.isEditable && it.isEnabled } != null }
                    val filename = requireNotNull(findNode { it.isEditable && it.isEnabled })
                    assertTrue(filename.performAction(AccessibilityNodeInfo.ACTION_SET_TEXT, Bundle().apply {
                        putCharSequence(AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE, name)
                    }))
                    await { findNode { it.viewIdResourceName?.endsWith(":id/button1") == true && it.isEnabled && it.isClickable } != null }
                    val save = requireNotNull(findNode {
                        it.viewIdResourceName?.endsWith(":id/button1") == true && it.isEnabled && it.isClickable
                    })
                    assertTrue(save.performAction(AccessibilityNodeInfo.ACTION_CLICK))
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
        await { findNode { it.contentDescription?.toString() in setOf("Show roots", "Show navigation drawer") } != null }
        click(requireNotNull(findNode { it.contentDescription?.toString() in setOf("Show roots", "Show navigation drawer") }))
        await { findNode { it.text?.toString() == "Downloads" && it.isEnabled } != null }
        click(requireNotNull(findNode { it.text?.toString() == "Downloads" && it.isEnabled }))
        await {
            findNode { it.text?.toString() == "Downloads" } != null &&
                findNode { it.viewIdResourceName?.endsWith(":id/button1") == true && it.isEnabled } != null
        }
    }

    private fun click(start: AccessibilityNodeInfo) {
        var node: AccessibilityNodeInfo? = start
        repeat(8) {
            val current = node ?: throw AssertionError("Picker target has no clickable ancestor")
            if (current.isClickable && current.isEnabled) {
                assertTrue(current.performAction(AccessibilityNodeInfo.ACTION_CLICK)); return
            }
            node = current.parent
        }
        throw AssertionError("Picker target exceeds bounded ancestry")
    }

    private fun foreground(host: MainActivity): Boolean = !host.isDestroyed && !host.isFinishing &&
        host.hasWindowFocus() && (host.application as ControllerApplication).isCurrentForegroundControllerHost(host)

    private fun pickerVisible(): Boolean =
        instrumentation.uiAutomation.rootInActiveWindow?.packageName?.toString()?.contains("documentsui") == true

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
        val deadline = SystemClock.elapsedRealtime() + 30_000L
        do { if (condition()) return; SystemClock.sleep(50) } while (SystemClock.elapsedRealtime() < deadline)
        throw AssertionError("Native document-picker observation deadline")
    }
}
