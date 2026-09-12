// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote

import android.app.LocaleManager
import android.content.Context
import android.content.res.Configuration
import android.content.res.Resources
import android.os.Build
import android.os.LocaleList
import java.util.Locale

/** Presentation preference only. No controller state, keys or credential storage.
 * API 33+ uses Android's per-app setting; older devices store only this allowlisted
 * tag in device-protected preferences so locked-boot notices can use it safely.
 * Context snapshots do not recreate Activities or renew native operations. */
internal object AppLanguage {
    val supported = setOf("ko", "en", "fr", "de", "ja", "zh-Hans", "zh-Hant", "es", "pt-BR", "pt-PT", "ar")
    private const val PREFERENCES = "presentation_language_v1"
    private const val KEY = "language"
    private const val MIGRATED = "android_locale_manager_migrated"

    fun valid(value: String): Boolean = value == "system" || value in supported

    internal fun match(tag: String): String? {
        val locale = Locale.forLanguageTag(tag)
        return when (locale.language) {
            "zh" -> if (locale.script == "Hant" || (locale.script != "Hans" && locale.country in setOf("TW", "HK", "MO"))) "zh-Hant" else "zh-Hans"
            "pt" -> if (locale.country == "PT") "pt-PT" else "pt-BR"
            else -> locale.language.takeIf { it in supported }
        }
    }

    private fun manager(context: Context): LocaleManager =
        requireNotNull(context.getSystemService(LocaleManager::class.java))

    fun systemLocales(context: Context): List<String> {
        val locales = if (Build.VERSION.SDK_INT >= 33) manager(context).systemLocales
            else Resources.getSystem().configuration.locales
        return (0 until locales.size()).take(16).map { locales[it].toLanguageTag() }
    }

    fun preference(context: Context): String {
        if (Build.VERSION.SDK_INT >= 33) {
            val locales = manager(context).applicationLocales
            if (locales.isEmpty) return "system"
            return (0 until locales.size()).mapNotNull { match(locales[it].toLanguageTag()) }.firstOrNull() ?: "en"
        }
        return context.createDeviceProtectedStorageContext().getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
            .getString(KEY, "system")?.takeIf(::valid) ?: "system"
    }

    fun effective(context: Context): String {
        val chosen = preference(context)
        return if (chosen != "system") chosen else systemLocales(context).firstNotNullOfOrNull(::match) ?: "en"
    }

    fun context(context: Context): Context {
        // A broken language preference must not stop the foreground service.
        // This fallback concerns presentation only, never authentication/state.
        val locale = Locale.forLanguageTag(try { effective(context) } catch (_: Exception) { "en" })
        val configuration = Configuration(context.resources.configuration)
        configuration.setLocales(LocaleList(locale))
        configuration.setLayoutDirection(locale)
        return context.createConfigurationContext(configuration)
    }

    fun text(context: Context, resource: Int): String = this.context(context).getString(resource)

    fun set(context: Context, language: String) {
        require(valid(language))
        if (Build.VERSION.SDK_INT >= 33) {
            manager(context).applicationLocales = if (language == "system") LocaleList.getEmptyLocaleList()
                else LocaleList.forLanguageTags(language)
        } else {
            check(context.createDeviceProtectedStorageContext().getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
                .edit().putString(KEY, language).commit())
        }
    }

    /** Preserve a pre-33 explicit choice across an OS upgrade, once. An existing
     * Android choice wins. The marker makes a later Android 'system' choice
     * authoritative instead of repeatedly restoring the old preference. */
    fun migrateLegacyPreference(context: Context) {
        if (Build.VERSION.SDK_INT < 33) return
        val preferences = context.createDeviceProtectedStorageContext()
            .getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
        if (preferences.getBoolean(MIGRATED, false)) return
        val legacy = preferences.getString(KEY, "system")
        val locales = manager(context)
        val restore = locales.applicationLocales.isEmpty && legacy != null && legacy in supported
        // Commit consumption first: a later failure must not replay a legacy
        // choice over the user's subsequent Android language selection.
        check(preferences.edit().putBoolean(MIGRATED, true).commit())
        if (restore) {
            locales.applicationLocales = LocaleList.forLanguageTags(requireNotNull(legacy))
        }
    }
}
