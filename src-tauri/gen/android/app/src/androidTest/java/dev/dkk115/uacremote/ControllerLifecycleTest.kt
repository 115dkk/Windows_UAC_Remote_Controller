// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote

import android.app.Notification
import android.app.NotificationManager
import android.content.pm.ApplicationInfo
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.SystemClock
import android.os.UserManager
import android.provider.Settings
import android.util.Base64
import android.view.View
import android.view.ViewGroup
import android.webkit.WebView
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import dev.dkk115.uacremote.background.ApplicationPolicyActor
import dev.dkk115.uacremote.background.BootComponentState
import dev.dkk115.uacremote.background.ControllerForegroundService
import dev.dkk115.uacremote.background.ControllerServiceState
import dev.dkk115.uacremote.background.ControllerStatusNotificationRenderer
import dev.dkk115.uacremote.background.PolicyOwnerPhase
import dev.dkk115.uacremote.background.ServiceControlResult
import java.io.File
import java.security.MessageDigest
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** Real product/JNI lifecycle only. No key generation, enrollment, auth or request fixtures.
 * Host observations BEFORE instrumentation establish boot/update behavior; launching this
 * test can restart the target process and therefore cannot itself establish autoboot. */
@RunWith(AndroidJUnit4::class)
class ControllerLifecycleTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val arguments = InstrumentationRegistry.getArguments()
    private val ownerField = ControllerApplication::class.java.getDeclaredField("policyActor").apply {
        // Read-only, in-process identity assertion. Never exported or used to change ownership.
        isAccessible = true
    }

    private data class Observed(
        val ready: Boolean, val stopped: Boolean, val component: BootComponentState,
        val actor: ApplicationPolicyActor?, val phase: PolicyOwnerPhase?, val notification: Boolean,
        val state: ControllerServiceState, val diagnostics: List<String>,
    )

    @Test fun nativeLifecyclePhase() {
        val context = instrumentation.targetContext
        assertEquals("dev.dkk115.uacremote", context.packageName)
        assertEquals("dev.dkk115.uacremote.test", instrumentation.context.packageName)
        assertEquals(36, Build.VERSION.SDK_INT)
        assertEquals("x86_64", Build.SUPPORTED_ABIS.first())
        assertTrue(Build.HARDWARE == "ranchu" || Build.HARDWARE == "goldfish")
        assertTrue(context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0)
        assertTrue(context.getSystemService(UserManager::class.java)?.isUserUnlocked == true)
        assertTrue(context.applicationInfo.splitSourceDirs.isNullOrEmpty())
        assertTrue(instrumentation.context.applicationInfo.splitSourceDirs.isNullOrEmpty())
        val phase = arguments.getString("phase") ?: error("Missing fixed lifecycle phase")
        assertTrue(phase in setOf("initial", "verify-enabled", "stop", "verify-stopped", "start"))
        val nonce = arguments.getString("nonce") ?: error("Missing receipt nonce")
        assertTrue(nonce.matches(Regex("[0-9a-f]{32}")))
        val appHash = apkHash(context.applicationInfo.sourceDir)
        val testHash = apkHash(instrumentation.context.applicationInfo.sourceDir)
        assertEquals(arguments.getString("app_sha256"), appHash)
        assertEquals(arguments.getString("test_sha256"), testHash)
        val checks = JSONObject()
        var scenario = ActivityScenario.launch(MainActivity::class.java)
        try {
            awaitWebView(scenario, "initial Activity document")
            checks.put("initialWebViewReady", true)
            when (phase) {
                "initial" -> {
                    val original = await(scenario, "initial native READY") { it.ready }
                    assertEquals(BootComponentState.DEFAULT, original.component)
                    assertNotNull(original.actor)
                    assertTrue(original.notification)
                    scenario.recreate()
                    awaitWebView(scenario, "recreated Activity document")
                    checks.put("recreatedWebViewReady", true)
                    val recreated = await(scenario, "recreated native READY") { it.ready }
                    assertSame(original.actor, recreated.actor)
                    checks.put("sameOwnerAfterRecreate", true)
                    onHost(scenario) { assertEquals(ServiceControlResult.REQUESTED, ControllerForegroundService.startIfEnabled(it)) }
                    val repeated = await(scenario, "repeated start native READY") { it.ready }
                    assertSame(original.actor, repeated.actor)
                    checks.put("sameOwnerAfterRepeatedStart", true)
                    stop(scenario)
                    val closed = await(scenario, "actual old owner CLOSED") { it.stopped && it.phase == PolicyOwnerPhase.CLOSED }
                    assertSame(original.actor, closed.actor)
                    checks.put("oldOwnerClosed", true)
                    scenario.close()
                    scenario = ActivityScenario.launch(MainActivity::class.java)
                    awaitWebView(scenario, "relaunched Activity document")
                    checks.put("relaunchedWebViewReady", true)
                    assertStopped(scenario)
                    checks.put("manualRelaunchStayedDisabled", true)
                    start(scenario)
                    val replacement = await(scenario, "explicit replacement READY") { it.ready }
                    assertNotSame(original.actor, replacement.actor)
                    assertEquals(BootComponentState.ENABLED, replacement.component)
                    checks.put("explicitStartCreatedOwnerAfterClose", true)
                }
                "verify-enabled" -> assertTrue(await(scenario, "enabled native READY") { it.ready }.notification)
                "stop" -> {
                    await(scenario, "native READY before stop") { it.ready }
                    stop(scenario)
                    await(scenario, "actual native CLOSED after stop") { it.stopped && it.phase == PolicyOwnerPhase.CLOSED }
                    checks.put("oldOwnerClosed", true)
                }
                "verify-stopped" -> assertStopped(scenario)
                "start" -> { assertStopped(scenario); start(scenario) }
            }
            awaitWebView(scenario, "completed phase document")
            checks.put("finalWebViewReady", true)
            val final = observe(scenario)
            val expectsStopped = phase == "stop" || phase == "verify-stopped"
            assertEquals(expectsStopped, final.stopped)
            assertEquals(!expectsStopped, final.ready)
            assertEquals(!expectsStopped, final.notification)
            if (!expectsStopped) assertEquals(PolicyOwnerPhase.READY, final.phase)
            val bootCount = Settings.Global.getInt(context.contentResolver, Settings.Global.BOOT_COUNT)
            assertTrue(bootCount >= 0)
            val receipt = JSONObject().put("version", 1).put("phase", phase).put("nonce", nonce)
                .put("appSha256", appHash).put("testSha256", testHash)
                .put("package", context.packageName).put("sdk", Build.VERSION.SDK_INT)
                .put("abi", Build.SUPPORTED_ABIS.first()).put("bootCount", bootCount)
                .put("ready", final.ready).put("stopped", final.stopped)
                .put("component", final.component.name).put("ownerPhase", final.phase?.name ?: "NONE")
                .put("notificationPresent", final.notification).put("checks", checks)
            val bytes = receipt.toString().toByteArray(Charsets.UTF_8)
            assertTrue(bytes.size <= 4096)
            instrumentation.sendStatus(0, Bundle().apply {
                putString("uac_lifecycle_receipt", Base64.encodeToString(bytes, Base64.NO_WRAP))
            })
        } finally { scenario.close() }
    }

    private fun start(scenario: ActivityScenario<MainActivity>) {
        onHost(scenario) { assertEquals(ServiceControlResult.REQUESTED, ControllerForegroundService.startExplicit(it)) }
        val observed = await(scenario, "explicit native READY") { it.ready }
        assertEquals(BootComponentState.ENABLED, observed.component)
        assertTrue(observed.notification)
    }

    private fun stop(scenario: ActivityScenario<MainActivity>) {
        onHost(scenario) { assertEquals(ServiceControlResult.REQUESTED, ControllerForegroundService.stopExplicit(it)) }
        assertStopped(scenario)
    }

    private fun assertStopped(scenario: ActivityScenario<MainActivity>) {
        val observed = await(scenario, "STOPPED, closed/absent owner, disabled receiver") {
            it.stopped && (it.phase == null || it.phase == PolicyOwnerPhase.CLOSED) && !it.notification
        }
        assertEquals(BootComponentState.DISABLED, observed.component)
        // Give already queued onStart/receiver work a bounded chance to contradict the assertion.
        val until = SystemClock.elapsedRealtime() + 500L
        while (SystemClock.elapsedRealtime() < until) {
            assertTrue(observe(scenario).stopped)
            SystemClock.sleep(50L)
        }
    }

    private fun onHost(scenario: ActivityScenario<MainActivity>, action: (MainActivity) -> Unit) {
        await(scenario, "actual resumed MainActivity") { true }
        scenario.onActivity { activity ->
            val app = activity.application as ControllerApplication
            assertTrue(app.isCurrentForegroundControllerHost(activity))
            action(activity)
        }
    }

    private fun observe(scenario: ActivityScenario<MainActivity>): Observed {
        var value: Observed? = null
        scenario.onActivity { activity ->
            val app = activity.application as ControllerApplication
            if (!app.isCurrentForegroundControllerHost(activity)) return@onActivity
            val state = app.observeControllerService(activity)
            val actor = ownerField.get(app) as? ApplicationPolicyActor
            val phase = actor?.lifecyclePhase()
            val notifications = activity.getSystemService(NotificationManager::class.java).activeNotifications
            val found = notifications.singleOrNull { it.id == ControllerStatusNotificationRenderer.NOTIFICATION_ID }
            if (found != null) {
                assertEquals(ControllerStatusNotificationRenderer.CHANNEL_ID, found.notification.channelId)
                assertTrue(found.notification.flags and Notification.FLAG_FOREGROUND_SERVICE != 0)
                assertTrue(found.notification.flags and Notification.FLAG_ONGOING_EVENT != 0)
            }
            value = Observed(
                state.state == ControllerServiceState.LOCAL_SETTINGS_READY && state.policyOwnerReady && actor != null && phase == PolicyOwnerPhase.READY,
                state.state == ControllerServiceState.STOPPED && !state.policyOwnerReady,
                ControllerForegroundService.componentState(activity), actor, phase, found != null,
                state.state, app.controllerLifecycleDiagnosticLines().orEmpty(),
            )
        }
        return value ?: throw HostNotResumed()
    }

    private fun await(scenario: ActivityScenario<MainActivity>, label: String, predicate: (Observed) -> Boolean): Observed {
        val until = SystemClock.elapsedRealtime() + 30_000L
        var last: Observed? = null
        do {
            val value = try { observe(scenario) } catch (_: HostNotResumed) { null }
            if (value != null) last = value
            if (value != null && predicate(value)) return value
            SystemClock.sleep(50L)
        } while (SystemClock.elapsedRealtime() < until)
        throw AssertionError("Lifecycle deadline: $label; state=${last?.state}; phase=${last?.phase}; component=${last?.component}; notification=${last?.notification}; ownerPresent=${last?.actor != null}; ${last?.diagnostics?.joinToString(",")}")
    }

    private class HostNotResumed : RuntimeException()

    private enum class WebReadiness { HOST_NOT_RESUMED, NO_ATTACHED_WEBVIEW, NONLOCAL_DOCUMENT, DOCUMENT_NOT_READY, CALLBACK_UNAVAILABLE, READY }

    /** Read only the actual current window. No loadUrl, new WebView, mock bridge,
     * DOM modification or navigation. evaluateJavascript and its callback run on
     * main; only the instrumentation thread waits, with one outstanding query. */
    private fun awaitWebView(scenario: ActivityScenario<MainActivity>, label: String) {
        val until = SystemClock.elapsedRealtime() + 30_000L
        var last: WebReadiness
        do {
            val done = CountDownLatch(1)
            val active = AtomicBoolean(true)
            val observed = AtomicReference(WebReadiness.HOST_NOT_RESUMED)
            scenario.onActivity { activity ->
                val app = activity.application as ControllerApplication
                if (!app.isCurrentForegroundControllerHost(activity)) { done.countDown(); return@onActivity }
                val web = attachedWebView(activity)
                if (web == null) { observed.set(WebReadiness.NO_ATTACHED_WEBVIEW); done.countDown(); return@onActivity }
                if (!localDocument(web.url)) { observed.set(WebReadiness.NONLOCAL_DOCUMENT); done.countDown(); return@onActivity }
                observed.set(WebReadiness.CALLBACK_UNAVAILABLE)
                try {
                    web.evaluateJavascript(WEB_READINESS_SCRIPT) { result ->
                        try {
                            if (active.get()) {
                                val current = app.isCurrentForegroundControllerHost(activity) && attachedWebView(activity) === web
                                observed.set(when {
                                    !current -> WebReadiness.NO_ATTACHED_WEBVIEW
                                    !localDocument(web.url) -> WebReadiness.NONLOCAL_DOCUMENT
                                    result == "true" -> WebReadiness.READY
                                    else -> WebReadiness.DOCUMENT_NOT_READY
                                })
                            }
                        } catch (_: RuntimeException) {
                            if (active.get()) observed.set(WebReadiness.CALLBACK_UNAVAILABLE)
                        } finally { done.countDown() }
                    }
                } catch (_: RuntimeException) { done.countDown() }
            }
            val remaining = until - SystemClock.elapsedRealtime()
            if (remaining <= 0 || !done.await(remaining.coerceAtMost(2_000L), TimeUnit.MILLISECONDS)) {
                active.set(false)
                throw AssertionError("WebView deadline: $label; callback unavailable")
            }
            active.set(false)
            last = observed.get()
            if (last == WebReadiness.READY) return
            SystemClock.sleep(50L)
        } while (SystemClock.elapsedRealtime() < until)
        throw AssertionError("WebView deadline: $label; state=$last")
    }

    private fun attachedWebView(activity: MainActivity): WebView? {
        val decor = activity.window.decorView
        val queue = ArrayDeque<Pair<View, Int>>()
        queue.add(decor to 0)
        var visited = 0
        var found: WebView? = null
        while (queue.isNotEmpty()) {
            val (view, depth) = queue.removeFirst()
            check(++visited <= 128 && depth <= 16) { "Bounded Activity view tree exceeded" }
            if (view is WebView) {
                if (view.isAttachedToWindow && view.isShown && view.width > 0 && view.height > 0 &&
                    view.windowToken == decor.windowToken && view.rootView === decor) {
                    check(found == null) { "Ambiguous attached WebViews" }
                    found = view
                }
            } else if (view is ViewGroup) {
                check(visited + queue.size + view.childCount <= 128) { "Bounded Activity view tree exceeded" }
                for (index in 0 until view.childCount) queue.add(view.getChildAt(index) to depth + 1)
            }
        }
        return found
    }

    private fun localDocument(raw: String?): Boolean {
        if (raw == null || raw.length !in 1..256) return false
        val url = Uri.parse(raw)
        val origin = (url.scheme in listOf("http", "https") && url.encodedAuthority == "tauri.localhost") ||
            (url.scheme == "tauri" && url.encodedAuthority == "localhost")
        return origin && url.path in listOf("", "/", "/index.html") && url.encodedQuery == null
    }

    private companion object {
        // Selectors come from ui/index.html, main.tsx and App.tsx. Require the
        // real Android React shell, not an empty mount or launch/error placeholder.
        // Return one boolean only: never expose document/request text or URLs.
        val WEB_READINESS_SCRIPT = """
            (() => {
              const u = new URL(location.href);
              const local = ((u.protocol === 'http:' || u.protocol === 'https:') && u.hostname === 'tauri.localhost') ||
                (u.protocol === 'tauri:' && u.hostname === 'localhost');
              if (!local || u.port || u.username || u.password || u.search ||
                  !['', '/', '/index.html'].includes(u.pathname) || document.readyState !== 'complete' ||
                  document.title !== '휴대폰 승인' || document.documentElement.lang !== 'ko') return false;
              const visible = e => {
                if (!e || !e.isConnected) return false;
                const s = getComputedStyle(e), r = e.getBoundingClientRect();
                return s.display !== 'none' && s.visibility === 'visible' && Number(s.opacity) > 0 && r.width > 0 && r.height > 0;
              };
              const root = document.getElementById('root');
              const shell = root && root.querySelector(':scope > .app-shell.phone-shell');
              const main = shell && shell.querySelector('main#main-content.main-scroll');
              const heading = main && main.querySelector('.page-header h1');
              const nav = shell && shell.querySelector('.navigation-shell nav');
              const current = nav && nav.querySelector('button[aria-current="page"]');
              return [document.body, root, shell, main, heading, nav, current].every(visible) &&
                heading.textContent.trim().length > 0 && current.textContent.trim().length > 0 &&
                nav.querySelectorAll('.navigation-item').length === 4;
            })()
        """.trimIndent()
    }

    private fun apkHash(path: String): String {
        val file = File(path)
        assertTrue(file.isFile && file.length() in 1L..268_435_456L)
        val digest = MessageDigest.getInstance("SHA-256")
        var count = 0L
        file.inputStream().use { input ->
            val buffer = ByteArray(65_536)
            while (true) {
                val read = input.read(buffer)
                if (read < 0) break
                count += read
                assertTrue(count <= 268_435_456L)
                digest.update(buffer, 0, read)
            }
        }
        assertEquals(file.length(), count)
        return digest.digest().joinToString("") { "%02x".format(it.toInt() and 255) }
    }
}
