// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote

import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.view.KeyEvent
import android.view.View
import android.view.ViewGroup
import android.webkit.WebView
import androidx.lifecycle.Lifecycle
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.util.concurrent.CountDownLatch
import java.util.concurrent.FutureTask
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

/** Actual installed product/physical WebView and Android Back key, on the
 * disposable lifecycle AVD. No browser Escape or direct native close substitute.
 */
@RunWith(AndroidJUnit4::class)
class LanguageBackInstrumentationTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val main = Handler(Looper.getMainLooper())

    @Test fun systemBackCancelsDraftAndPreservesActivityThenNormalBackLeaves() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            var captured: MainActivity? = null
            scenario.onActivity { captured = it }
            val host = requireNotNull(captured)
            val app = host.application as ControllerApplication
            await { onMain { app.isCurrentForegroundControllerHost(host) && host.hasWindowFocus() } }
            await { eval(host, "!!document.querySelector('.app-settings-button:not(:disabled)')") == "true" }
            val originalPreference = onMain { AppLanguage.preference(host) }
            val originalLocale = onMain { AppLanguage.effective(host) }
            repeat(2) {
                // Javascript click() does not focus like a user interaction.
                // Set the real toolbar's focus before testing focus restoration.
                assertEquals("true", eval(host, OPEN_SETTINGS))
                await { eval(host, OPEN) == "true" }
                val initialChoice = eval(host, CHOICE)
                // Select a different draft through the actual rendered radio.
                assertEquals("true", eval(host, """
                    (()=>{const radios=[...document.querySelectorAll('.language-settings input[type=radio]')];
                    const other=radios.find(r=>!r.checked); if(!other)return false; other.click(); return true})()
                """.trimIndent()))
                assertNotEquals(initialChoice, eval(host, CHOICE))
                instrumentation.sendKeyDownUpSync(KeyEvent.KEYCODE_BACK)
                await { eval(host, OPEN) == "false" }
                assertTrue(onMain { app.isCurrentForegroundControllerHost(host) && !host.isFinishing })
                assertEquals(originalPreference, onMain { AppLanguage.preference(host) })
                assertEquals(originalLocale, onMain { AppLanguage.effective(host) })
                assertEquals("true", eval(host, "document.activeElement===document.querySelector('.app-settings-button')"))
                // Reopening confirms the draft was discarded, not merely hidden.
                assertEquals("true", eval(host, OPEN_SETTINGS))
                await { eval(host, OPEN) == "true" }
                assertEquals(initialChoice, eval(host, CHOICE))
                instrumentation.sendKeyDownUpSync(KeyEvent.KEYCODE_BACK)
                await { eval(host, OPEN) == "false" }
            }
            // Deterministic lifecycle edge on the actual WebView: retire a
            // queued no-dialog reply before it reaches the main-thread callback.
            // This artificial focus notification is not gesture evidence.
            onMain {
                host.onBackPressedDispatcher.onBackPressed()
                host.onWindowFocusChanged(false)
                host.onWindowFocusChanged(true)
            }
            assertEquals("false", eval(host, OPEN))
            instrumentation.waitForIdleSync()
            assertTrue(onMain { app.isCurrentForegroundControllerHost(host) && !host.isFinishing })
            // The callback must not trap users in the app when no web dialog is open.
            instrumentation.sendKeyDownUpSync(KeyEvent.KEYCODE_BACK)
            await { scenario.state != Lifecycle.State.RESUMED }
        }
    }

    private fun webView(host: MainActivity): WebView {
        val decor = host.window.decorView
        val queue = ArrayDeque<View>(); queue.add(decor)
        var count = 0
        var result: WebView? = null
        while (queue.isNotEmpty()) {
            val view = queue.removeFirst()
            assertTrue(++count <= 128)
            if (view is WebView && view.isAttachedToWindow && view.rootView === decor) {
                assertNull(result); result = view
            } else if (view is ViewGroup) {
                assertTrue(count + queue.size + view.childCount <= 128)
                for (index in 0 until view.childCount) queue.add(view.getChildAt(index))
            }
        }
        return requireNotNull(result)
    }

    private fun eval(host: MainActivity, script: String): String {
        val done = CountDownLatch(1)
        val result = AtomicReference<String?>(null)
        onMain {
            assertTrue((host.application as ControllerApplication).isCurrentForegroundControllerHost(host))
            val original = webView(host)
            original.evaluateJavascript(script) { value ->
                if (!host.isDestroyed && !host.isFinishing && webView(host) === original && value.length <= 32) result.set(value)
                done.countDown()
            }
        }
        assertTrue("Original WebView callback required", done.await(10, TimeUnit.SECONDS))
        return requireNotNull(result.get())
    }

    private fun <T> onMain(action: () -> T): T {
        val task = FutureTask<T> { action() }
        assertTrue(main.post(task))
        return try { task.get(3, TimeUnit.SECONDS) }
        catch (error: Exception) { task.cancel(false); throw AssertionError("Main operation failed", error) }
    }

    private fun await(condition: () -> Boolean) {
        val deadline = SystemClock.elapsedRealtime() + 30_000L
        do { if (condition()) return; SystemClock.sleep(50) } while (SystemClock.elapsedRealtime() < deadline)
        throw AssertionError("Android Back observation deadline")
    }

    companion object {
        private const val OPEN_SETTINGS = "(()=>{const b=document.querySelector('.app-settings-button');b.focus();b.click();return true})()"
        private const val OPEN = "!!document.querySelector('dialog.language-settings[open]')"
        private const val CHOICE = "[...document.querySelectorAll('.language-settings input[type=radio]')].findIndex(r=>r.checked)"
    }
}
