// SPDX-License-Identifier: GPL-2.0-or-later

package dev.dkk115.uacremote

import android.app.KeyguardManager
import android.app.NotificationManager
import android.content.ComponentName
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.content.pm.ResolveInfo
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.provider.Settings
import android.webkit.WebView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.Lifecycle
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import dev.dkk115.uacremote.background.PolicyOwnerBounds
import dev.dkk115.uacremote.background.PolicyReply
import dev.dkk115.uacremote.background.PolicyStatus
import dev.dkk115.uacremote.background.BootServicePolicy
import dev.dkk115.uacremote.background.ControllerForegroundService
import dev.dkk115.uacremote.background.ControllerServiceObservation
import dev.dkk115.uacremote.background.ServiceControlResult
import dev.dkk115.uacremote.background.NativeRequestActionResult
import dev.dkk115.uacremote.background.NativeRequestReadReply
import dev.dkk115.uacremote.background.NativeRequestRules
import org.json.JSONObject
import org.json.JSONTokener
import java.util.concurrent.atomic.AtomicBoolean

/**
 * One immutable physical Activity/WebView command adapter. Every queued closure,
 * busy flag and reply remains owned by this instance after facade replacement.
 */
internal class DeviceStateActivityCommands(
    private val activity: MainActivity,
    private val webView: WebView,
    private val binding: DeviceStateViewBinding<MainActivity, WebView>,
    private val emitRequestWake: () -> Unit,
) {
    private val host: AppCompatActivity? = activity
    internal fun matches(view: WebView): Boolean =
        view === webView && binding.matches(activity, webView) &&
            webView.context === activity && !activity.isDestroyed && !activity.isFinishing
    internal fun retire() {
        binding.retire()
        (activity.application as? ControllerApplication)?.retirePairingScanner(activity, binding)
        (activity.application as? ControllerApplication)?.observeRequestChanges(activity, null)
    }

    // Accessed only on Android's main thread. A later foreground lifecycle entry
    // permits another explicit settings request; resuming never launches one.
    private var settingsLaunchPending = false
    private val serviceMain = Handler(Looper.getMainLooper())
    private val serviceCommandPending = AtomicBoolean(false)
    private val serviceStopPending = AtomicBoolean(false)
    private val requestCommands = HashSet<String>()
    private enum class ServiceCommand { READ, START, STOP }
    private sealed class ServiceReply {
        class Observation(val value: ControllerServiceObservation) : ServiceReply()
        class Mutation(val value: ServiceControlResult) : ServiceReply()
    }

    fun onResume() {
        settingsLaunchPending = false
        bindRequestWake()
    }

    fun bind() { bindRequestWake() }
    private fun bindRequestWake() {
        val bind = Runnable {
            if (binding.matches(activity, webView) && !activity.isDestroyed && !activity.isFinishing) {
                (activity.application as? ControllerApplication)?.observeRequestChanges(activity) {
                    if (isForeground()) try { emitRequestWake() } catch (_: Exception) { }
                }
            }
        }
        if (Looper.myLooper() == Looper.getMainLooper()) bind.run() else serviceMain.post(bind)
    }

    fun controllerRequests(invoke: Invoke) = readRequests(invoke, false)
    fun controllerRequestDetails(invoke: Invoke) = readRequests(invoke, true)

    private fun readRequests(invoke: Invoke, details: Boolean) {
        val fields = requestArguments(invoke.getRawArgs(), if (details) setOf("locator") else emptySet())
        val locator = fields?.get("locator")
        if (fields == null || (details && (locator == null || !NativeRequestRules.locator(locator)))) {
            resolveRequestStatus(invoke, NativeRequestActionResult.UNAVAILABLE); return
        }
        requestCommand(invoke, if (details) "details" else "list") { finish ->
            val app = activity.application as? ControllerApplication
            if (app == null || !isForeground()) finish { requestStatus(NativeRequestActionResult.UNAVAILABLE) }
            else app.readControllerRequests(activity, locator) { reply ->
                finish {
                    if (!isForeground()) requestStatus(NativeRequestActionResult.UNAVAILABLE)
                    else when (reply) {
                        is NativeRequestReadReply.Failed -> requestStatus(if (reply.status == NativeRequestActionResult.BUSY) reply.status else NativeRequestActionResult.UNAVAILABLE)
                        is NativeRequestReadReply.Data -> {
                            if (!app.validControllerRequestReply(activity, reply.value)) requestStatus(NativeRequestActionResult.UNAVAILABLE)
                            else JSObject().apply { put("status", "ok"); put(if (details) "detailsJson" else "requestsJson", reply.value.json) }
                        }
                    }
                }
            }
        }
    }

    fun controllerRequestReview(invoke: Invoke) {
        if (requestArguments(invoke.getRawArgs(), emptySet()) == null) { resolveRequestStatus(invoke, NativeRequestActionResult.UNAVAILABLE); return }
        requestCommand(invoke, "review") { finish ->
            finish {
                val value = if (isForeground()) (activity.application as? ControllerApplication)?.controllerRequestReview(activity) else null
                if (value == null) requestStatus(NativeRequestActionResult.UNAVAILABLE)
                else JSObject().apply { put("status", "ok"); put("locator", value.locator ?: JSONObject.NULL); put("revision", value.revision) }
            }
        }
    }

    fun controllerRequestAction(invoke: Invoke) {
        val fields = requestArguments(invoke.getRawArgs(), setOf("locator", "action"))
        val locator = fields?.get("locator")
        val action = fields?.get("action")?.let { NativeRequestRules.action(it) }
        if (locator == null || !NativeRequestRules.locator(locator) || action == null) { resolveRequestStatus(invoke, NativeRequestActionResult.UNAVAILABLE); return }
        requestCommand(invoke, "action") { finish ->
            val app = activity.application as? ControllerApplication
            if (app == null || !isForeground()) finish { requestStatus(NativeRequestActionResult.UNAVAILABLE) }
            else app.controllerRequestAction(activity, locator, action) { result -> finish { requestStatus(result) } }
        }
    }

    /** Exact closed string keys only; duplicate/extra/trailing values fail. */
    private fun requestArguments(raw: String, expected: Set<String>): Map<String, String>? = try {
        if (raw.length > 512) null
        else if (expected.isEmpty()) if (raw.trim() in setOf("{}", "null")) emptyMap() else null
        else {
            val input = JSONTokener(raw)
            val values = LinkedHashMap<String, String>()
            if (input.nextClean() != '{') null else {
                var valid = true
                for (index in expected.indices) {
                    if (input.nextClean() != '"') { valid = false; break }
                    val key = input.nextString('"')
                    if (key !in expected || values.containsKey(key) || input.nextClean() != ':' || input.nextClean() != '"') { valid = false; break }
                    values[key] = input.nextString('"')
                    if (input.nextClean() != if (index == expected.size - 1) '}' else ',') { valid = false; break }
                }
                if (valid && values.keys == expected && input.nextClean() == '\u0000') values else null
            }
        }
    } catch (_: Exception) { null }

    private fun requestCommand(invoke: Invoke, name: String, action: ((() -> JSObject) -> Unit) -> Unit) {
        if (!synchronized(requestCommands) { requestCommands.add(name) }) { resolveRequestStatus(invoke, NativeRequestActionResult.BUSY); return }
        val finished = AtomicBoolean(false)
        val timeout = Runnable {
            if (finished.compareAndSet(false, true)) {
                synchronized(requestCommands) { requestCommands.remove(name) }
                resolveRequestStatus(invoke, NativeRequestActionResult.UNAVAILABLE)
            }
        }
        val finish: (() -> JSObject) -> Unit = { value ->
            val deliver = Runnable {
                if (finished.compareAndSet(false, true)) {
                    serviceMain.removeCallbacks(timeout)
                    synchronized(requestCommands) { requestCommands.remove(name) }
                    val result = try { if (!binding.matches(activity, webView) || activity.isDestroyed || activity.isFinishing) requestStatus(NativeRequestActionResult.UNAVAILABLE) else value() }
                        catch (_: Exception) { requestStatus(NativeRequestActionResult.UNAVAILABLE) }
                    try { invoke.resolve(result) } catch (_: Exception) { }
                }
            }
            if (Looper.myLooper() == Looper.getMainLooper()) deliver.run() else serviceMain.post(deliver)
        }
        if (!serviceMain.postDelayed(timeout, PolicyOwnerBounds.RESPONSE_TIMEOUT_MILLIS)) { timeout.run(); return }
        val run = Runnable { try { action(finish) } catch (_: Exception) { finish { requestStatus(NativeRequestActionResult.UNAVAILABLE) } } }
        if (Looper.myLooper() == Looper.getMainLooper()) run.run() else if (!serviceMain.post(run)) timeout.run()
    }
    private fun requestStatus(value: NativeRequestActionResult): JSObject = JSObject().apply { put("status", value.wire) }
    private fun resolveRequestStatus(invoke: Invoke, value: NativeRequestActionResult) {
        val deliver = Runnable { try { invoke.resolve(requestStatus(value)) } catch (_: Exception) { } }
        if (Looper.myLooper() == Looper.getMainLooper()) deliver.run() else serviceMain.post(deliver)
    }

    fun controllerService(invoke: Invoke) = serviceCommand(invoke, ServiceCommand.READ)

    fun startControllerService(invoke: Invoke) = serviceCommand(invoke, ServiceCommand.START)

    fun stopControllerService(invoke: Invoke) = serviceCommand(invoke, ServiceCommand.STOP)

    /** Fixed operations only: one read/start reply and one downward stop reply
     * per physical plugin. STOP can cancel a busy START; the Application still
     * owns the sole persistence slot. Reading constructs no actor/native owner. */
    private fun serviceCommand(invoke: Invoke, command: ServiceCommand) {
        val validArguments = try { BootServicePolicy.acceptsServiceArguments(invoke.getRawArgs()) }
            catch (_: Exception) { false }
        if (!validArguments) {
            rejectServiceCommand(invoke, command, ServiceControlResult.NOT_ALLOWED)
            return
        }
        val pendingReply = if (command == ServiceCommand.STOP) serviceStopPending else serviceCommandPending
        if (!pendingReply.compareAndSet(false, true)) {
            rejectServiceCommand(invoke, command, ServiceControlResult.UNAVAILABLE)
            return
        }
        val started = SystemClock.elapsedRealtime()
        val replied = AtomicBoolean(false)
        fun finish(reply: ServiceReply) {
            if (!replied.compareAndSet(false, true)) return
            // Release this physical adapter's reply slot, not the Application's
            // persistence slot. A timed-out writer remains globally owned.
            pendingReply.set(false)
            resolveServiceReply(invoke, reply)
        }
        val work = Runnable {
            try {
                if (BootServicePolicy.serviceCommandExpired(started, SystemClock.elapsedRealtime())) {
                    finish(serviceFailure(command, ServiceControlResult.UNAVAILABLE))
                } else {
                    val owner = activity.application as? ControllerApplication
                    if (owner == null) finish(serviceFailure(command, ServiceControlResult.UNAVAILABLE))
                    else when (command) {
                        ServiceCommand.READ -> finish(ServiceReply.Observation(owner.observeControllerService(activity)))
                        ServiceCommand.START -> if (isForeground()) ControllerForegroundService.startExplicit(activity, started) {
                            finish(ServiceReply.Mutation(it))
                        } else finish(ServiceReply.Mutation(ServiceControlResult.NOT_ALLOWED))
                        ServiceCommand.STOP -> if (isForeground()) ControllerForegroundService.stopExplicit(activity, started) {
                            finish(ServiceReply.Mutation(it))
                        } else finish(ServiceReply.Mutation(ServiceControlResult.NOT_ALLOWED))
                    }
                }
            } catch (_: Exception) {
                // Never retry an accepted operation or log exception/intent data.
                finish(serviceFailure(command, ServiceControlResult.UNAVAILABLE))
            }
        }
        if (Looper.myLooper() == Looper.getMainLooper()) work.run()
        else if (!serviceMain.post(work)) {
            finish(serviceFailure(command, ServiceControlResult.UNAVAILABLE))
        }
    }

    private fun rejectServiceCommand(invoke: Invoke, command: ServiceCommand, result: ServiceControlResult) {
        resolveServiceReply(invoke, serviceFailure(command, result))
    }

    private fun serviceFailure(command: ServiceCommand, result: ServiceControlResult): ServiceReply =
        if (command == ServiceCommand.READ) ServiceReply.Observation(ControllerServiceObservation.UNAVAILABLE)
        else ServiceReply.Mutation(result)

    private fun resolveServiceReply(invoke: Invoke, reply: ServiceReply) {
        when (reply) {
            is ServiceReply.Observation -> resolveServiceObservation(invoke, reply.value)
            is ServiceReply.Mutation -> resolveServiceMutation(invoke, reply.value)
        }
    }

    private fun resolveServiceObservation(invoke: Invoke, observation: ControllerServiceObservation) {
        val result = JSObject()
        result.put("state", observation.state.wireValue)
        // JSONObject.put(key, null) removes the key; the DTO requires explicit null.
        result.put("bootEnabled", observation.bootEnabled ?: JSONObject.NULL)
        result.put("canStart", observation.canStart)
        result.put("canStop", observation.canStop)
        result.put("policyOwnerReady", observation.policyOwnerReady)
        try { invoke.resolve(result) } catch (_: Exception) { /* detached reply only */ }
    }

    private fun resolveServiceMutation(invoke: Invoke, outcome: ServiceControlResult) {
        val result = JSObject()
        result.put("status", outcome.wireValue)
        try { invoke.resolve(result) } catch (_: Exception) { /* never retry a native request */ }
    }

    fun controllerPolicy(invoke: Invoke) {
        val raw = invoke.getRawArgs()
        if (raw.length > MAX_EMPTY_ARGUMENT_LENGTH || raw.trim().let { it != "null" && it != "{}" }) {
            resolvePolicy(invoke, PolicyReply.Failed(PolicyStatus.UNAVAILABLE))
            return
        }
        val owner = activity.application as? ControllerApplication
        if (owner == null) resolvePolicy(invoke, PolicyReply.Failed(PolicyStatus.UNAVAILABLE))
        else owner.readControllerPolicy { result -> resolvePolicy(invoke, result) }
    }

    fun controllerHistory(invoke: Invoke) {
        if (!acceptsNoArguments(invoke)) return
        val owner = activity.application as? ControllerApplication
        if (owner == null) resolveHistory(invoke, PolicyReply.Failed(PolicyStatus.UNAVAILABLE))
        else owner.readControllerHistory { result -> resolveHistory(invoke, result) }
    }

    fun clearControllerHistory(invoke: Invoke) {
        if (!acceptsNoArguments(invoke)) return
        val owner = activity.application as? ControllerApplication
        if (owner == null) resolveHistory(invoke, PolicyReply.Failed(PolicyStatus.UNAVAILABLE))
        else owner.clearControllerHistory { result -> resolveHistory(invoke, result) }
    }

    fun saveControllerPolicy(invoke: Invoke) {
        val policy = policyArgument(invoke.getRawArgs())
        if (policy == null) {
            resolvePolicy(invoke, PolicyReply.Failed(PolicyStatus.INVALID_POLICY))
            return
        }
        val owner = activity.application as? ControllerApplication
        if (owner == null) resolvePolicy(invoke, PolicyReply.Failed(PolicyStatus.UNAVAILABLE))
        else owner.saveControllerPolicy(policy) { result -> resolvePolicy(invoke, result) }
    }

    /** Exactly one quoted string field; duplicates/extra fields/trailing data are rejected. */
    private fun policyArgument(raw: String): String? = try {
        if (raw.length > PolicyOwnerBounds.MAX_RAW_ARGUMENT_CHARS) null else {
            val input = JSONTokener(raw)
            if (input.nextClean() != '{' || input.nextClean() != '"' ||
                input.nextString('"') != "policyJson" || input.nextClean() != ':' || input.nextClean() != '"') null
            else {
                val value = input.nextString('"')
                if (input.nextClean() != '}' || input.nextClean() != '\u0000' || !PolicyOwnerBounds.validPolicyString(value)) null
                else value
            }
        }
    } catch (_: Exception) { null }

    private fun resolvePolicy(invoke: Invoke, reply: PolicyReply) {
        activity.runOnUiThread {
            val result = JSObject()
            if (!binding.matches(activity, webView) || activity.isDestroyed || activity.isFinishing) result.put("status", PolicyStatus.UNAVAILABLE.wireValue)
            else when (reply) {
                is PolicyReply.Committed -> {
                    result.put("status", "ok")
                    result.put("policyJson", reply.policyJson)
                }
                is PolicyReply.HistoryCommitted -> result.put("status", PolicyStatus.UNAVAILABLE.wireValue)
                is PolicyReply.Failed -> result.put("status", reply.status.wireValue)
            }
            try { invoke.resolve(result) } catch (_: Exception) {
                // The old Activity/Invoke can disappear during rotation. Never
                // shut down the Application owner or retry a committed write.
            }
        }
    }

    private fun resolveHistory(invoke: Invoke, reply: PolicyReply) {
        activity.runOnUiThread {
            val result = JSObject()
            if (!binding.matches(activity, webView) || activity.isDestroyed || activity.isFinishing) result.put("status", PolicyStatus.UNAVAILABLE.wireValue)
            else when (reply) {
                is PolicyReply.HistoryCommitted -> {
                    result.put("status", "ok")
                    result.put("historyJson", reply.historyJson)
                }
                is PolicyReply.Committed -> result.put("status", PolicyStatus.UNAVAILABLE.wireValue)
                is PolicyReply.Failed -> result.put("status", reply.status.wireValue)
            }
            try { invoke.resolve(result) } catch (_: Exception) {
                // Activity loss does not reset or retry a committed history clear.
            }
        }
    }

    fun readiness(invoke: Invoke) {
        if (!acceptsNoArguments(invoke)) return
        activity.runOnUiThread {
            val observation = observeDeviceReadiness(
                foreground = isForeground(),
                readSecureLock = ::deviceSecure,
                readNotificationsEnabled = ::notificationsEnabled,
                settingsResolvable = {
                    !settingsLaunchPending && resolveSecuritySettings() != null
                },
                notificationSettingsResolvable = {
                    !settingsLaunchPending && resolveNotificationSettings() != null
                },
            )
            val result = JSObject()
            result.put("screenLock", observation.screenLock.wireValue)
            result.put("notifications", observation.notifications.wireValue)
            result.put("canOpenLockSettings", observation.canOpenLockSettings)
            result.put("canOpenNotificationSettings", observation.canOpenNotificationSettings)
            result.put("canOpenPairingScanner", isForeground() &&
                (activity.application as? ControllerApplication)?.canOpenPairingScanner(activity) == true)
            invoke.resolve(result)
        }
    }

    fun openPairingScanner(invoke: Invoke) {
        if (!acceptsNoArguments(invoke)) return
        activity.runOnUiThread {
            val owner = activity.application as? ControllerApplication
            fun reply(status: dev.dkk115.uacremote.pairing.PairingScannerLaunch) {
                val value = if (isForeground()) status else dev.dkk115.uacremote.pairing.PairingScannerLaunch.UNAVAILABLE
                val result = JSObject(); result.put("status", value.wireValue)
                try { invoke.resolve(result) } catch (_: Exception) { }
            }
            if (owner == null || !isForeground()) reply(dev.dkk115.uacremote.pairing.PairingScannerLaunch.UNAVAILABLE)
            else owner.openPairingScanner(activity, binding, ::isForeground, ::reply)
        }
    }

    fun openLockSettings(invoke: Invoke) {
        if (!acceptsNoArguments(invoke)) return
        activity.runOnUiThread {
            if (!isForeground()) {
                rejectSettings(invoke)
                return@runOnUiThread
            }
            // Do not trust the earlier readiness snapshot or a renderer flag.
            when (readSecureLockObservation(::deviceSecure)) {
                SecureLockObservation.CONFIGURED -> {
                    invoke.resolve()
                    return@runOnUiThread
                }
                SecureLockObservation.UNAVAILABLE -> {
                    rejectReadiness(invoke)
                    return@runOnUiThread
                }
                SecureLockObservation.MISSING -> Unit
            }
            if (settingsLaunchPending) {
                invoke.reject("보안 설정 화면을 이미 열고 있어요.", "lock_settings_pending")
                return@runOnUiThread
            }
            val intent = try {
                resolveSecuritySettings()
            } catch (_: Exception) {
                null
            }
            if (intent == null) {
                rejectSettings(invoke)
                return@runOnUiThread
            }
            // A lock could have been configured while package resolution ran.
            // Opening settings is not needed once the native observation is true.
            when (readSecureLockObservation(::deviceSecure)) {
                SecureLockObservation.CONFIGURED -> {
                    invoke.resolve()
                    return@runOnUiThread
                }
                SecureLockObservation.UNAVAILABLE -> {
                    rejectReadiness(invoke)
                    return@runOnUiThread
                }
                SecureLockObservation.MISSING -> Unit
            }
            if (!isForeground()) {
                rejectSettings(invoke)
                return@runOnUiThread
            }
            settingsLaunchPending = true
            try {
                activity.startActivity(intent)
            } catch (_: Exception) {
                settingsLaunchPending = false
                rejectSettings(invoke)
                return@runOnUiThread
            }
            // Only launch completion is reported. No lock-setting or
            // authentication success is inferred from opening an OS screen.
            invoke.resolve()
        }
    }

    private fun isForeground(): Boolean {
        val currentHost = host ?: return false
        return binding.matches(activity, webView) && !currentHost.isFinishing && !currentHost.isDestroyed &&
            currentHost.lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED) &&
            (activity.application as? ControllerApplication)?.isCurrentForegroundControllerHost(activity) == true
    }

    fun openNotificationSettings(invoke: Invoke) {
        if (!acceptsNoArguments(invoke)) return
        activity.runOnUiThread {
            if (!isForeground() || settingsLaunchPending) {
                rejectNotificationSettings(invoke)
                return@runOnUiThread
            }
            val intent = try { resolveNotificationSettings() } catch (_: Exception) { null }
            if (intent == null || !isForeground()) {
                rejectNotificationSettings(invoke)
                return@runOnUiThread
            }
            settingsLaunchPending = true
            try {
                activity.startActivity(intent)
            } catch (_: Exception) {
                settingsLaunchPending = false
                rejectNotificationSettings(invoke)
                return@runOnUiThread
            }
            // Launch only. The OS owns the setting; no permission grant or
            // notification delivery is inferred from startActivity returning.
            invoke.resolve()
        }
    }

    private fun deviceSecure(): Boolean? {
        // isKeyguardSecure includes a SIM PIN; isDeviceLocked is only a current
        // lock observation. Neither answers whether a secure device lock exists.
        return activity.getSystemService(KeyguardManager::class.java)?.isDeviceSecure
    }

    private fun notificationsEnabled(): Boolean? {
        // Calling-package permission/enabled state only. This is not a claim
        // about a notification channel, Do Not Disturb or actual delivery.
        return activity.getSystemService(NotificationManager::class.java)
            ?.areNotificationsEnabled()
    }

    private fun resolveSecuritySettings(): Intent? = resolveSystemSettings(Intent(Settings.ACTION_SECURITY_SETTINGS))

    private fun resolveNotificationSettings(): Intent? = resolveSystemSettings(
        Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS)
            .putExtra(Settings.EXTRA_APP_PACKAGE, activity.packageName),
    )

    /** The only callers construct fixed native actions and this app's own package. */
    private fun resolveSystemSettings(intent: Intent): Intent? {
        val manager = activity.packageManager
        val candidates = querySystemSettings(manager, intent)
        if (candidates.size > MAX_SETTINGS_CANDIDATES) return null
        val resolved = resolveSystemSettings(manager, intent)?.activityInfo ?: return null
        // A generic system chooser is not an actual handler for this action.
        if (candidates.none { candidate ->
                candidate.activityInfo?.let { info ->
                    info.packageName == resolved.packageName && info.name == resolved.name
                } == true
            }
        ) return null
        val application = resolved.applicationInfo ?: return null
        if (!resolved.exported || !resolved.enabled || !application.enabled) return null
        if (application.flags and ApplicationInfo.FLAG_SYSTEM == 0) return null
        // Platform-signed system handlers are inside the intact Android OS
        // trust boundary. Ordinary installed apps cannot impersonate this target.
        if (manager.checkSignatures("android", resolved.packageName) != PackageManager.SIGNATURE_MATCH) {
            return null
        }
        val requiredPermission = resolved.permission
        if (requiredPermission != null &&
            activity.checkSelfPermission(requiredPermission) != PackageManager.PERMISSION_GRANTED
        ) return null
        // The action and target come only from native OS resolution. No package,
        // component, URI, intent extras or flags are accepted from the WebView.
        return intent.setComponent(ComponentName(resolved.packageName, resolved.name))
    }

    @Suppress("DEPRECATION") // Typed flags were added at API 33; minSdk is 30.
    private fun querySystemSettings(manager: PackageManager, intent: Intent): List<ResolveInfo> {
        val flags = PackageManager.MATCH_DEFAULT_ONLY or PackageManager.MATCH_SYSTEM_ONLY
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            manager.queryIntentActivities(intent, PackageManager.ResolveInfoFlags.of(flags.toLong()))
        } else {
            manager.queryIntentActivities(intent, flags)
        }
    }

    @Suppress("DEPRECATION") // Typed flags were added at API 33; minSdk is 30.
    private fun resolveSystemSettings(manager: PackageManager, intent: Intent): ResolveInfo? {
        val flags = PackageManager.MATCH_DEFAULT_ONLY or PackageManager.MATCH_SYSTEM_ONLY
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            manager.resolveActivity(intent, PackageManager.ResolveInfoFlags.of(flags.toLong()))
        } else {
            manager.resolveActivity(intent, flags)
        }
    }

    private fun acceptsNoArguments(invoke: Invoke): Boolean {
        // Rust sends unit as null; an empty object is also a no-argument call.
        // Reject any supplied readiness/target fields without parsing or logging.
        val arguments = invoke.getRawArgs()
        if (arguments.length <= MAX_EMPTY_ARGUMENT_LENGTH &&
            arguments.trim().let { it == "null" || it == "{}" }
        ) return true
        invoke.reject("이 요청을 처리할 수 없어요. 앱에서 다시 시도해 주세요.", "invalid_device_state_arguments")
        return false
    }

    private fun rejectReadiness(invoke: Invoke) {
        // Never pass an Exception to Invoke.reject: Tauri logs exception text.
        invoke.reject("휴대폰 잠금 상태를 확인하지 못했어요.", "mobile_state_unavailable")
    }

    private fun rejectSettings(invoke: Invoke) {
        invoke.reject("보안 설정 화면을 열지 못했어요. 휴대폰 설정에서 확인해 주세요.", "lock_settings_unavailable")
    }

    private fun rejectNotificationSettings(invoke: Invoke) {
        invoke.reject("알림 설정 화면을 열지 못했어요. 휴대폰 설정에서 이 앱의 알림을 확인해 주세요.", "notification_settings_unavailable")
    }

    private companion object {
        const val MAX_SETTINGS_CANDIDATES = 32
        const val MAX_EMPTY_ARGUMENT_LENGTH = 32
    }
}

internal enum class SecureLockObservation(val wireValue: String) {
    CONFIGURED("configured"),
    MISSING("missing"),
    UNAVAILABLE("unavailable"),
}

internal enum class NotificationObservation(val wireValue: String) {
    ALLOWED("allowed"),
    DENIED("denied"),
    UNAVAILABLE("unavailable"),
}

internal data class DeviceReadinessObservation(
    val screenLock: SecureLockObservation,
    val notifications: NotificationObservation,
    val canOpenLockSettings: Boolean,
    val canOpenNotificationSettings: Boolean,
) {
    companion object {
        val UNAVAILABLE = DeviceReadinessObservation(
            SecureLockObservation.UNAVAILABLE,
            NotificationObservation.UNAVAILABLE,
            false,
            false,
        )
    }
}

internal fun readSecureLockObservation(read: () -> Boolean?): SecureLockObservation = try {
    when (read()) {
        true -> SecureLockObservation.CONFIGURED
        false -> SecureLockObservation.MISSING
        null -> SecureLockObservation.UNAVAILABLE
    }
} catch (_: Exception) {
    SecureLockObservation.UNAVAILABLE
}

/** Pure error/observation mapping; test probes are never production OS evidence. */
internal fun observeDeviceReadiness(
    foreground: Boolean,
    readSecureLock: () -> Boolean?,
    readNotificationsEnabled: () -> Boolean?,
    settingsResolvable: () -> Boolean,
    notificationSettingsResolvable: () -> Boolean = { false },
): DeviceReadinessObservation {
    if (!foreground) return DeviceReadinessObservation.UNAVAILABLE
    val secureLock = readSecureLockObservation(readSecureLock)
    val notifications = try {
        when (readNotificationsEnabled()) {
            true -> NotificationObservation.ALLOWED
            false -> NotificationObservation.DENIED
            null -> NotificationObservation.UNAVAILABLE
        }
    } catch (_: Exception) {
        NotificationObservation.UNAVAILABLE
    }
    val canOpenSettings = secureLock == SecureLockObservation.MISSING && try {
        settingsResolvable()
    } catch (_: Exception) {
        false
    }
    val canOpenNotificationSettings = notifications == NotificationObservation.DENIED && try {
        notificationSettingsResolvable()
    } catch (_: Exception) {
        false
    }
    return DeviceReadinessObservation(secureLock, notifications, canOpenSettings, canOpenNotificationSettings)
}
