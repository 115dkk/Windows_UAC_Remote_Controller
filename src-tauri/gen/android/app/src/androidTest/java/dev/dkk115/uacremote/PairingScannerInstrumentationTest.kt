// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote

import android.Manifest
import android.app.KeyguardManager
import android.content.Context
import android.content.pm.PackageManager
import android.content.res.Configuration
import android.graphics.Bitmap
import android.graphics.Canvas
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.os.UserManager
import android.view.ContextThemeWrapper
import android.view.View
import android.view.ViewGroup
import android.view.WindowManager
import android.view.inspector.WindowInspector
import android.webkit.WebView
import android.widget.TextView
import androidx.lifecycle.Lifecycle
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import dev.dkk115.uacremote.background.PolicyOwnerPhase
import dev.dkk115.uacremote.pairing.PairingScannerState
import dev.dkk115.uacremote.pairing.PairingScannerView
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.security.MessageDigest
import java.util.Locale
import java.util.concurrent.CountDownLatch
import java.util.concurrent.FutureTask
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

/** ROOT-only isolated API36 fixture. No permission grant, PIN, QR injection or native bypass here. */
@RunWith(AndroidJUnit4::class)
class PairingScannerInstrumentationTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val main = Handler(Looper.getMainLooper())
    private class Input(val nonce: String, val appSha: String, val testSha: String)

    @Test fun nativeDialogKeepsSecureFlagAndCancelsOnHostStop() {
        val input = inputs()
        val context = instrumentation.targetContext
        assertTrue(context.getSystemService(UserManager::class.java)?.isUserUnlocked == true)
        assertTrue(context.getSystemService(KeyguardManager::class.java)?.isDeviceSecure == true)
        assertEquals(PackageManager.PERMISSION_GRANTED, context.checkSelfPermission(Manifest.permission.CAMERA))
        assertTrue(context.packageManager.hasSystemFeature(PackageManager.FEATURE_CAMERA_ANY))
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            var activity: MainActivity? = null
            scenario.onActivity { activity = it }
            val host = requireNotNull(activity)
            val app = host.application as ControllerApplication
            try { await { onMain { app.canOpenPairingScanner(host) } } }
            catch (error: AssertionError) {
                // Fixed diagnostic lines only (owner phase, service, activation); never payloads.
                throw AssertionError("Scanner gate stayed closed: ${onMain { app.controllerLifecycleDiagnosticLines() }}", error)
            }
            val originalActor = onMain { actor(app) }
            try { await { eval(host, BUTTON_READY) == "true" } }
            catch (error: AssertionError) {
                // Fixed shape only: whether the client rendered the button, the native gate and owner lines.
                val client = eval(host, BUTTON_STATE)
                val gate = onMain { app.canOpenPairingScanner(host) }
                throw AssertionError("Scanner button never became ready: client=$client nativeGate=$gate ${onMain { app.controllerLifecycleDiagnosticLines() }}", error)
            }
            assertEquals("\"clicked\"", eval(host, CLICK_BUTTON))
            try { await { onMain { scannerWindow() != null } } }
            catch (error: AssertionError) {
                // Fixed tokens only: whether the native open ran and how it ended, plus the owner lines.
                val launch = onMain { app.lastPairingScannerLaunch }
                val gate = onMain { app.canOpenPairingScanner(host) }
                throw AssertionError("Scanner window never appeared: launch=$launch nativeGate=$gate ${onMain { app.controllerLifecycleDiagnosticLines() }}", error)
            }
            assertTrue(onMain { secureScannerWindow() })
            await { onMain { scannerMessage() == host.getString(R.string.pairing_scanner_scanning) } }
            assertFalse(onMain { app.canOpenPairingScanner(host) })
            onMain {
                val close = scannerWindow()?.findViewById<View>(R.id.pairing_scanner_close)
                assertNotNull(close); assertTrue(close!!.performClick())
            }
            await { onMain { scannerWindow() == null && app.canOpenPairingScanner(host) } }
            // Only the original empty release wake refreshes this capability;
            // the test does not force a snapshot reload or mutate client state.
            await { eval(host, BUTTON_READY) == "true" }
            assertEquals("\"clicked\"", eval(host, CLICK_BUTTON))
            await { onMain { scannerMessage() == host.getString(R.string.pairing_scanner_scanning) } }
            scenario.moveToState(Lifecycle.State.STARTED)
            await { onMain { scannerWindow() == null } }
            scenario.moveToState(Lifecycle.State.RESUMED)
            await { onMain { app.canOpenPairingScanner(host) } }
            assertSame(originalActor, onMain { actor(app) })
            assertTrue(onMain { app.controllerLifecycleDiagnosticLines()?.contains("owner_phase=${PolicyOwnerPhase.READY.name}") == true })
        }
        receipt(input, "native-dialog", listOf("actualCurrentWebViewButtonOpened", "secureWindow", "cameraScanning",
            "entryUnavailableWhileOpen", "closeReleased", "entryRestoredAfterRelease", "backgroundCancelled", "originalActorPreserved"))
    }

    @Test fun renderNativeViewsWithNoQrFixture() {
        val input = inputs()
        val root = File(instrumentation.targetContext.cacheDir, "pairing-scanner-fixtures/${input.nonce}")
        assertFalse("Fresh native view fixture directory required", root.exists())
        assertTrue(root.mkdirs())
        var count = 0
        for (dark in listOf(false, true)) for (large in listOf(false, true)) for (state in PairingScannerState.values()) {
            val bitmap = onMain {
                val config = Configuration(instrumentation.targetContext.resources.configuration).apply {
                    fontScale = if (large) 2f else 1f
                    densityDpi = 160 // Explicit component viewport, not the device's OS font/size setting.
                    uiMode = (uiMode and Configuration.UI_MODE_NIGHT_MASK.inv()) or
                        (if (dark) Configuration.UI_MODE_NIGHT_YES else Configuration.UI_MODE_NIGHT_NO)
                }
                val configured = instrumentation.targetContext.createConfigurationContext(config)
                val view = PairingScannerView(ContextThemeWrapper(configured, R.style.Theme_PairingScanner), {}, {})
                // COMPARE needs a code to draw its controls. This is an explicitly synthetic gallery
                // fixture, never a value the production View could supply on its own.
                view.render(state, permissionSettingsAvailable = true,
                    comparisonCode = if (state == PairingScannerState.COMPARE) "123456" else null)
                view.measure(View.MeasureSpec.makeMeasureSpec(390, View.MeasureSpec.EXACTLY),
                    View.MeasureSpec.makeMeasureSpec(844, View.MeasureSpec.EXACTLY))
                view.layout(0, 0, 390, 844)
                // onSizeChanged adjusts the native preview's bounded height.
                // Detached fixture views receive no later Choreographer pass.
                view.measure(View.MeasureSpec.makeMeasureSpec(390, View.MeasureSpec.EXACTLY),
                    View.MeasureSpec.makeMeasureSpec(844, View.MeasureSpec.EXACTLY))
                view.layout(0, 0, 390, 844)
                Bitmap.createBitmap(390, 844, Bitmap.Config.ARGB_8888).also { view.draw(Canvas(it)) }
            }
            val name = "${state.name.lowercase(Locale.ROOT)}-${if (dark) "dark" else "light"}-${if (large) "large" else "normal"}.png"
            val output = File(root, name)
            assertTrue(output.createNewFile())
            try { output.outputStream().use { assertTrue(bitmap.compress(Bitmap.CompressFormat.PNG, 100, it)) } }
            finally { bitmap.recycle() }
            assertTrue(output.length() in 1..2_000_000L)
            count++
        }
        assertEquals(PairingScannerState.values().size * 4, count)
        assertEquals(68, count)
        receipt(input, "native-view-render", listOf("ownedNativeViewOnly", "noQrOrCameraFixture", "normalAndLargeText",
            "lightAndDark", "allFixtureFilesWritten"))
    }

    private fun inputs(): Input {
        val args = InstrumentationRegistry.getArguments()
        val nonce = requireNotNull(args.getString("scan_nonce"))
        val app = requireNotNull(args.getString("app_sha256"))
        val test = requireNotNull(args.getString("test_sha256"))
        assertTrue(nonce.matches(Regex("[0-9a-f]{32}")))
        assertTrue(app.matches(Regex("[0-9a-f]{64}")) && test.matches(Regex("[0-9a-f]{64}")))
        assertEquals(36, Build.VERSION.SDK_INT)
        assertEquals("x86_64", Build.SUPPORTED_ABIS.first())
        assertEquals("dev.dkk115.uacremote", instrumentation.targetContext.packageName)
        assertEquals("dev.dkk115.uacremote.test", instrumentation.context.packageName)
        assertEquals(app, apkHash(instrumentation.targetContext))
        assertEquals(test, apkHash(instrumentation.context))
        return Input(nonce, app, test)
    }

    private fun apkHash(context: Context): String {
        val digest = MessageDigest.getInstance("SHA-256")
        var bytes = 0L
        File(context.applicationInfo.sourceDir).inputStream().use { input ->
            val buffer = ByteArray(64 * 1024)
            while (true) {
                val count = input.read(buffer); if (count < 0) break
                bytes += count; assertTrue(bytes <= 256L * 1024 * 1024); digest.update(buffer, 0, count)
            }
        }
        assertTrue(bytes > 0)
        return digest.digest().joinToString("") { (it.toInt() and 0xff).toString(16).padStart(2, '0') }
    }

    private fun receipt(input: Input, case: String, checks: List<String>) {
        val value = JSONObject().put("version", 1).put("case", case).put("nonce", input.nonce)
            .put("appSha256", input.appSha).put("testSha256", input.testSha).put("completed", true)
            .put("checks", JSONObject().apply { for (check in checks) put(check, true) })
        instrumentation.sendStatus(0, Bundle().apply { putString("UAC_PAIRING_SCAN_RECEIPT_V1", value.toString()) })
    }

    private fun actor(app: ControllerApplication): Any = app.javaClass.getDeclaredField("policyActor").let {
        it.isAccessible = true; requireNotNull(it.get(app)) // Identity only; no Rust/key/storage fields are read.
    }
    private fun scannerWindow(): View? {
        val roots = WindowInspector.getGlobalWindowViews()
        assertTrue(roots.size <= 16)
        val matches = roots.filter { it.findViewById<View>(R.id.pairing_scanner_root) != null && it.isAttachedToWindow }
        assertTrue(matches.size <= 1)
        return matches.singleOrNull()
    }
    private fun secureScannerWindow(): Boolean = (scannerWindow()?.layoutParams as? WindowManager.LayoutParams)?.let {
        it.flags and WindowManager.LayoutParams.FLAG_SECURE != 0
    } == true
    private fun scannerMessage(): String? = scannerWindow()?.findViewById<TextView>(R.id.pairing_scanner_message)?.text?.toString()

    private fun webView(host: MainActivity): WebView {
        val decor = host.window.decorView
        val queue = ArrayDeque<Pair<View, Int>>(); queue.add(decor to 0)
        var count = 0; var result: WebView? = null
        while (queue.isNotEmpty()) {
            val (view, depth) = queue.removeFirst(); assertTrue(++count <= 128 && depth <= 16)
            if (view is WebView && view.isAttachedToWindow && view.isShown && view.width > 0 && view.height > 0 &&
                view.windowToken == decor.windowToken && view.rootView === decor) {
                assertNull(result); result = view
            }
            if (view is ViewGroup && view !is WebView) {
                assertTrue(count + queue.size + view.childCount <= 128)
                for (index in 0 until view.childCount) queue.add(view.getChildAt(index) to depth + 1)
            }
        }
        return requireNotNull(result)
    }

    private fun eval(host: MainActivity, script: String): String {
        val done = CountDownLatch(1); val active = AtomicBoolean(true); val value = AtomicReference<String?>(null)
        onMain {
            val app = host.application as ControllerApplication
            assertTrue(app.isCurrentForegroundControllerHost(host))
            val original = webView(host)
            val raw = requireNotNull(original.url)
            assertTrue(raw.length in 1..256)
            val url = android.net.Uri.parse(raw)
            val local = (url.scheme in listOf("http", "https") && url.encodedAuthority == "tauri.localhost") ||
                (url.scheme == "tauri" && url.encodedAuthority == "localhost")
            assertTrue(local && url.path in listOf("", "/", "/index.html") && url.encodedQuery == null)
            original.evaluateJavascript(script) { observed ->
                try {
                    if (active.get() && app.isCurrentForegroundControllerHost(host) && webView(host) === original && observed != null && observed.length <= 32) value.set(observed)
                } catch (_: Throwable) { /* Late observation only, never repeat the command. */ }
                finally { done.countDown() }
            }
        }
        if (!done.await(2, TimeUnit.SECONDS)) { active.set(false); throw AssertionError("Native scan Javascript callback unavailable") }
        active.set(false)
        return value.get() ?: throw AssertionError("Original native scan view changed")
    }

    private fun <T> onMain(action: () -> T): T {
        val task = FutureTask<T> { action() }
        assertTrue(main.post(task))
        return try { task.get(3, TimeUnit.SECONDS) }
        catch (_: Exception) { task.cancel(false); throw AssertionError("Native scan main operation failed or timed out; completion unconfirmed") }
    }
    private fun await(condition: () -> Boolean) {
        val deadline = SystemClock.elapsedRealtime() + 30_000L
        do { if (condition()) return; SystemClock.sleep(50) } while (SystemClock.elapsedRealtime() < deadline)
        throw AssertionError("Native scanner observation deadline")
    }
    companion object {
        private const val BUTTON_READY = "(()=>{const b=document.querySelector('button[data-pairing-scanner=\"open\"]');return !!b&&!b.disabled;})()"
        private const val BUTTON_STATE = "(()=>{const b=document.querySelector('button[data-pairing-scanner=\"open\"]');return JSON.stringify({present:!!b,disabled:b?b.disabled:null,buttons:document.querySelectorAll('button').length,title:document.title});})()"
        private const val CLICK_BUTTON = "(()=>{const b=document.querySelector('button[data-pairing-scanner=\"open\"]');if(!b||b.disabled)return 'missing';b.click();return 'clicked';})()"
    }
}
