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
import android.webkit.WebResourceRequest
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import dev.dkk115.uacremote.background.ApplicationPolicyActor
import dev.dkk115.uacremote.background.BootComponentState
import dev.dkk115.uacremote.background.BootServicePolicy
import dev.dkk115.uacremote.background.ControllerForegroundService
import dev.dkk115.uacremote.background.ControllerServiceState
import dev.dkk115.uacremote.background.ControllerStatusNotificationRenderer
import dev.dkk115.uacremote.background.PolicyOwnerPhase
import dev.dkk115.uacremote.background.ServiceControlResult
import java.io.File
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.security.MessageDigest
import java.util.Collections
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.FutureTask
import java.util.concurrent.TimeoutException
import java.util.concurrent.ExecutionException
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import org.json.JSONObject
import org.json.JSONTokener
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
                    stalePostMessageProbe(scenario, checks)
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

    private class ActualView(val activity: MainActivity, val view: RustWebView, val logicalId: String, val url: String,
        val documentStartScripts: Boolean) {
        override fun toString(): String = "ActualView([retained native instance])"
    }

    private fun actualView(scenario: ActivityScenario<MainActivity>): ActualView {
        var result: ActualView? = null
        onHost(scenario) { activity ->
            val view = attachedWebView(activity)
            assertTrue("Expected the actual product RustWebView", view is RustWebView)
            val actual = view as RustWebView
            assertTrue(localDocument(actual.url))
            assertTrue(actual.id.length in 1..128)
            result = ActualView(activity, actual, actual.id, actual.url!!, actual.isDocumentStartScriptEnabled)
        }
        return checkNotNull(result)
    }

    /** Extra real recreation AFTER the unchanged initial lifecycle sequence.
     * Both deliveries use byte-for-byte the CURRENT document's generated message;
     * only the actual Java WebView argument differs. No old nonce/malformed-input
     * negative, fake origin, key/auth request or production test endpoint. */
    private fun stalePostMessageProbe(scenario: ActivityScenario<MainActivity>, checks: JSONObject) {
        val before = await(scenario, "native READY before stale-origin probe") { it.ready }
        val retired = actualView(scenario)
        scenario.recreate()
        awaitWebView(scenario, "stale-origin replacement document")
        val after = await(scenario, "same native owner after probe recreation") { it.ready }
        assertSame(before.actor, after.actor)
        val current = actualView(scenario)
        assertNotSame(retired.view, current.view)
        assertNotSame(retired.activity, current.activity)
        onHost(scenario) {
            assertTrue(retired.activity.isDestroyed)
            assertFalse(retired.view.isAttachedToWindow)
        }
        // In real configuration recreation, both are the SAME logical WebView.
        assertTrue("Probe must not rely on an unknown old logical ID", retired.logicalId == current.logicalId)
        directCustomProtocolReadProbe(scenario, retired, current, before.actor, checks)
        try {
            val payload = captureMessage(scenario, current, ProbeCommand.STOP)
            assertTrue(evalProbe(scenario, current, PROBE_STATE_SCRIPT) == "\"pending\"")
            // Exact existing JNI postMessage entry, not direct native service API.
            // Wry derives provenance from this retained ORIGINAL Java object.
            nativeEntry { Rust.ipc(retired.view, current.logicalId, current.url, payload) }
            val until = SystemClock.elapsedRealtime() + BootServicePolicy.SERVICE_COMMAND_TIMEOUT_MILLIS + 250L
            do {
                val observed = observe(scenario)
                assertTrue("Retired view changed native readiness", observed.ready && observed.notification)
                assertSame(before.actor, observed.actor)
                assertTrue(observed.component == BootComponentState.ENABLED)
                SystemClock.sleep(50L)
            } while (SystemClock.elapsedRealtime() < until)
            // A stale reply must not resolve/reject the CURRENT view's callback.
            assertTrue(evalProbe(scenario, current, PROBE_STATE_SCRIPT) == "\"pending\"")
            checks.put("retiredPostMessagePreservedReadyOwner", true)

            nativeEntry { Rust.ipc(current.view, current.logicalId, current.url, payload) }
            val closed = await(scenario, "current-view IPC STOP actually CLOSED") { it.stopped && it.phase == PolicyOwnerPhase.CLOSED && !it.notification }
            assertSame(before.actor, closed.actor)
            assertEquals(BootComponentState.DISABLED, closed.component)
            val responseDeadline = SystemClock.elapsedRealtime() + 10_000L
            while (true) {
                val state = evalProbe(scenario, current, PROBE_STATE_SCRIPT)
                if (state == "\"resolved\"") break
                assertTrue("Current valid STOP IPC rejected or response deadline", state == "\"pending\"" && SystemClock.elapsedRealtime() < responseDeadline)
                SystemClock.sleep(50L)
            }
            checks.put("sameCurrentPostMessageStoppedOwner", true)
        } finally {
            // Immutable JVM strings are only released, not claimed zeroized.
            // No payload, invoke key or callback ID is logged or put in receipts.
            try { evalProbe(scenario, current, PROBE_CLEANUP_SCRIPT) } catch (_: Exception) { }
        }
        start(scenario)
        val restarted = await(scenario, "native READY after current-view IPC stop") { it.ready }
        assertNotSame(before.actor, restarted.actor)
        checks.put("staleOriginProbeRestartReady", true)
    }

    private enum class ProbeCommand { STOP, READ }

    private fun captureMessage(scenario: ActivityScenario<MainActivity>, current: ActualView, command: ProbeCommand): String {
        val encoded = evalProbe(scenario, current, if (command == ProbeCommand.STOP) CAPTURE_STOP_SCRIPT else CAPTURE_READ_SCRIPT)
        val payload = try { JSONTokener(encoded).nextValue() as? String } catch (_: Exception) { null }
        assertTrue("Genuine current IPC capture unavailable", payload != null && payload.length in 1..16_384)
        val valid = try {
            val message = JSONObject(payload!!)
            val body = message.getJSONObject("payload")
            val fixedCommand = if (command == ProbeCommand.STOP) message.getString("cmd") == "control_service" && body.length() == 1 && body.getString("action") == "stop"
                else message.getString("cmd") == "app_snapshot" && body.length() == 0
            fixedCommand &&
                message.getString("__TAURI_INVOKE_KEY__").length in 1..512 &&
                message.getLong("callback") in 0L..0xffff_ffffL && message.getLong("error") in 0L..0xffff_ffffL &&
                message.getLong("callback") != message.getLong("error")
        } catch (_: Exception) { false }
        assertTrue("Captured command did not match the fixed real invocation", valid)
        return payload!!
    }

    /** A test-owned HTTP carrier, not a fake native origin. It reproduces the
     * pinned ipc-protocol.js headers from a genuine CURRENT invocation. Android
     * normally routes these commands over postMessage and cannot read a request
     * body; parameterless app_snapshot is valid with the real empty-body parser.
     * This exercises native handleRequest, NOT framework fetch interception. */
    private class CapturedReadRequest(private val target: Uri, values: Map<String, String>) : WebResourceRequest {
        private val headers: MutableMap<String, String> = Collections.unmodifiableMap(LinkedHashMap(values))
        override fun getUrl(): Uri = target
        override fun isForMainFrame(): Boolean = false
        override fun isRedirect(): Boolean = false
        override fun hasGesture(): Boolean = false
        override fun getMethod(): String = "POST"
        override fun getRequestHeaders(): MutableMap<String, String> = headers
        override fun toString(): String = "CapturedReadRequest([private test memory])"
    }

    private fun directCustomProtocolReadProbe(scenario: ActivityScenario<MainActivity>, retired: ActualView,
        current: ActualView, expectedOwner: ApplicationPolicyActor?, checks: JSONObject) {
        try {
            val payload = captureMessage(scenario, current, ProbeCommand.READ)
            val request = try {
                val message = JSONObject(payload)
                val target = JSONTokener(evalProbe(scenario, current, PROBE_READ_URL_SCRIPT)).nextValue() as? String
                val origin = JSONTokener(evalProbe(scenario, current, PROBE_ORIGIN_SCRIPT)).nextValue() as? String
                assertTrue(target == "http://ipc.localhost/app_snapshot" || target == "https://ipc.localhost/app_snapshot")
                assertTrue(origin == "http://tauri.localhost" || origin == "https://tauri.localhost")
                CapturedReadRequest(Uri.parse(target!!), mapOf(
                    "Origin" to origin!!, "Content-Type" to "application/json",
                    "Tauri-Callback" to message.getLong("callback").toString(),
                    "Tauri-Error" to message.getLong("error").toString(),
                    "Tauri-Invoke-Key" to message.getString("__TAURI_INVOKE_KEY__"),
                ))
            } catch (_: Exception) { throw AssertionError("Current native READ carrier unavailable") }
            val rejected = nativeEntry {
                val response = Rust.handleRequest(retired.view, current.logicalId, request, current.documentStartScripts)
                try { response == null } finally { response?.data?.close() }
            }
            assertTrue("Retired actual view entered the custom protocol handler", rejected)
            val preserved = observe(scenario)
            assertTrue(preserved.ready && preserved.notification && preserved.component == BootComponentState.ENABLED)
            assertSame(expectedOwner, preserved.actor)

            // SAME carrier instance/headers, only the original Java view changes.
            val currentRead = nativeEntry {
                val response = Rust.handleRequest(current.view, current.logicalId, request, current.documentStartScripts)
                    ?: throw AssertionError("Current native READ response missing")
                val data = response.data ?: throw AssertionError("Current native READ body missing")
                data.use { input ->
                    assertTrue("Current READ HTTP status mismatch", response.statusCode == 200)
                    val success = response.responseHeaders?.entries?.filter { it.key.equals("Tauri-Response", ignoreCase = true) }.orEmpty()
                    assertTrue("Current READ was not a successful Tauri response", success.size == 1 && success.single().value == "ok")
                    val bytes = ByteArrayOutputStream()
                    val buffer = ByteArray(4096)
                    while (true) {
                        val count = input.read(buffer)
                        if (count < 0) break
                        assertTrue("Native READ body bound exceeded", bytes.size() + count <= 512 * 1024)
                        bytes.write(buffer, 0, count)
                    }
                    try {
                        val decoder = Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
                        val snapshot = JSONObject(decoder.decode(ByteBuffer.wrap(bytes.toByteArray())).toString())
                        val phone = snapshot.getJSONObject("phoneService")
                        snapshot.getInt("schemaVersion") == 3 && snapshot.getString("platform") == "android" &&
                            phone.getString("state") == "local_settings_ready" && phone.getBoolean("policyOwnerReady") && phone.getBoolean("bootEnabled")
                    } catch (_: Exception) { false }
                }
            }
            assertTrue("Current READ did not return the actual ready Android snapshot", currentRead)
            val afterRead = observe(scenario)
            assertTrue(afterRead.ready && afterRead.notification && afterRead.component == BootComponentState.ENABLED)
            assertSame(expectedOwner, afterRead.actor)
            checks.put("retiredNativeHttpReadRejected", true)
            checks.put("sameCurrentNativeHttpReadSucceeded", true)
        } finally {
            try { evalProbe(scenario, current, PROBE_CLEANUP_SCRIPT) } catch (_: Exception) { }
        }
    }

    private fun <T> nativeEntry(action: () -> T): T {
        // Mirrors the background JavascriptInterface/interception thread. Never
        // block Android main. A timeout does NOT claim native cancellation; fail
        // the test and do not perform subsequent probe actions or retry it.
        val task = FutureTask<T> { action() }
        Thread(task, "uac-physical-origin-test").apply { isDaemon = true; start() }
        return try { task.get(10, TimeUnit.SECONDS) }
        catch (_: TimeoutException) { throw AssertionError("Native entry deadline; completion unconfirmed") }
        catch (_: ExecutionException) { throw AssertionError("Native entry failed; private payload not logged") }
    }

    private fun evalProbe(scenario: ActivityScenario<MainActivity>, expected: ActualView, script: String): String {
        val done = CountDownLatch(1)
        val active = AtomicBoolean(true)
        val result = AtomicReference<String?>(null)
        onHost(scenario) { activity ->
            assertSame(expected.activity, activity)
            assertSame(expected.view, attachedWebView(activity))
            expected.view.evaluateJavascript(script) { value ->
                try {
                    val app = activity.application as ControllerApplication
                    if (active.get() && app.isCurrentForegroundControllerHost(activity) && attachedWebView(activity) === expected.view &&
                        value != null && value.length <= 32_768) result.set(value)
                } catch (_: RuntimeException) {
                    // Fixed failure only; never leak captured envelope contents.
                } finally { done.countDown() }
            }
        }
        if (!done.await(2_000L, TimeUnit.MILLISECONDS)) {
            active.set(false)
            throw AssertionError("Fixed IPC probe script callback unavailable")
        }
        active.set(false)
        return result.get() ?: throw AssertionError("Fixed IPC probe result unavailable")
    }

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
        // Pinned scripts/core.js and ipc-protocol.js use the synchronous Android
        // brownfield postMessage path. Guard mutability BEFORE invoking anything,
        // intercept exactly one generated envelope, then restore the native bridge
        // in the same JS turn. The production scripts/nonce are never replaced.
        val CAPTURE_STOP_SCRIPT = """
            (() => {
              const key = '__uacPhysicalOriginProbe';
              const api = window.__TAURI_INTERNALS__;
              const descriptor = Object.getOwnPropertyDescriptor(window, 'ipc');
              if (window[key] || !api || api.__TAURI_PATTERN__.pattern !== 'brownfield' ||
                  typeof api.ipc !== 'function' || typeof api.invoke !== 'function' || !descriptor ||
                  (!descriptor.configurable && !descriptor.writable)) return null;
              const original = window.ipc;
              if (!original || typeof original.postMessage !== 'function') return null;
              const state = { phase: 'pending', callback: null, error: null };
              let captured = null;
              const hook = { postMessage(message) {
                if (captured !== null || typeof message !== 'string' || message.length > 16384) throw new Error('Fixed IPC capture rejected');
                captured = message;
              }};
              try {
                if (descriptor.configurable) Object.defineProperty(window, 'ipc', { value: hook, configurable: true, writable: true });
                else window.ipc = hook;
                if (window.ipc !== hook) return null;
                Object.defineProperty(window, key, { value: state, configurable: true });
                api.invoke('control_service', { action: 'stop' }).then(
                  () => { state.phase = 'resolved'; }, () => { state.phase = 'rejected'; });
                if (captured === null) return null;
                const message = JSON.parse(captured);
                state.callback = message.callback; state.error = message.error;
                return captured;
              } catch (_) { return null; }
              finally { Object.defineProperty(window, 'ipc', descriptor); }
            })()
        """.trimIndent()
        val CAPTURE_READ_SCRIPT = CAPTURE_STOP_SCRIPT.replace("api.invoke('control_service', { action: 'stop' })", "api.invoke('app_snapshot', {})")
        const val PROBE_READ_URL_SCRIPT = "window.__TAURI_INTERNALS__.convertFileSrc('app_snapshot', 'ipc')"
        const val PROBE_ORIGIN_SCRIPT = "location.origin"
        const val PROBE_STATE_SCRIPT = "window.__uacPhysicalOriginProbe ? window.__uacPhysicalOriginProbe.phase : 'missing'"
        val PROBE_CLEANUP_SCRIPT = """
            (() => {
              const value = window.__uacPhysicalOriginProbe;
              if (value) {
                for (const id of [value.callback, value.error]) {
                  if (Number.isInteger(id)) window.__TAURI_INTERNALS__.unregisterCallback(id);
                }
                delete window.__uacPhysicalOriginProbe;
              }
              return true;
            })()
        """.trimIndent()
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
