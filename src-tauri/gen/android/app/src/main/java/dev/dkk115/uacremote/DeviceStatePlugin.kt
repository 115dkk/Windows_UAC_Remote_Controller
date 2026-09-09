// SPDX-License-Identifier: GPL-2.0-or-later

package dev.dkk115.uacremote

import android.app.Activity
import android.app.KeyguardManager
import android.app.NotificationManager
import android.content.ComponentName
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.content.pm.ResolveInfo
import android.os.Build
import android.provider.Settings
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.Lifecycle
import app.tauri.annotation.Command
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import dev.dkk115.uacremote.background.PolicyOwnerBounds
import dev.dkk115.uacremote.background.PolicyReply
import dev.dkk115.uacremote.background.PolicyStatus
import org.json.JSONTokener

/**
 * Foreground OS observations plus the Application-owned policy command adapter.
 * Neither readiness nor committed notification policy is approval evidence.
 *
 * Tauri 2.11.x instantiates the exact public (android.app.Activity) constructor.
 * The generated host is AppCompatActivity; an unexpected host fails unavailable
 * instead of relying on a throwing cast. No permission request, credential,
 * biometric, notification-posting or custom JNI API lives here. Policy writes
 * are delegated to the one real Rust owner; no settings are persisted by this plugin.
 */
@TauriPlugin
class DeviceStatePlugin(private val activity: Activity) : Plugin(activity) {
    private val host = activity as? AppCompatActivity

    // Accessed only on Android's main thread. A later foreground lifecycle entry
    // permits another explicit settings request; resuming never launches one.
    private var settingsLaunchPending = false

    override fun onResume() {
        settingsLaunchPending = false
    }

    @Command
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

    @Command
    fun controllerHistory(invoke: Invoke) {
        if (!acceptsNoArguments(invoke)) return
        val owner = activity.application as? ControllerApplication
        if (owner == null) resolveHistory(invoke, PolicyReply.Failed(PolicyStatus.UNAVAILABLE))
        else owner.readControllerHistory { result -> resolveHistory(invoke, result) }
    }

    @Command
    fun clearControllerHistory(invoke: Invoke) {
        if (!acceptsNoArguments(invoke)) return
        val owner = activity.application as? ControllerApplication
        if (owner == null) resolveHistory(invoke, PolicyReply.Failed(PolicyStatus.UNAVAILABLE))
        else owner.clearControllerHistory { result -> resolveHistory(invoke, result) }
    }

    @Command
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
            if (activity.isDestroyed || activity.isFinishing) result.put("status", PolicyStatus.UNAVAILABLE.wireValue)
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
            if (activity.isDestroyed || activity.isFinishing) result.put("status", PolicyStatus.UNAVAILABLE.wireValue)
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

    @Command
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
            invoke.resolve(result)
        }
    }

    @Command
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
        return !currentHost.isFinishing && !currentHost.isDestroyed &&
            currentHost.lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED)
    }

    @Command
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
