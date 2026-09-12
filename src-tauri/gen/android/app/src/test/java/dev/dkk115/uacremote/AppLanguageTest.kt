// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote

import org.junit.Assert.*
import org.junit.Test

/** Pure selection contracts; not proof of Android per-app setting persistence. */
class AppLanguageTest {
    @Test fun explicitPreferenceIsAClosedCanonicalAllowlist() {
        for (tag in listOf("system", "ko", "en", "fr", "de", "ja", "zh-Hans", "zh-Hant", "es", "pt-BR", "pt-PT", "ar")) {
            assertTrue(AppLanguage.valid(tag))
        }
        for (tag in listOf("", "EN", "fr-FR", "pt", "zh", "en-US", "../en", "ar\u202e", " system")) {
            assertFalse(AppLanguage.valid(tag))
        }
    }

    @Test fun systemLocalesResolveRegionsScriptsAndUnsupportedLanguages() {
        for ((source, expected) in mapOf("en-GB" to "en", "fr-CA" to "fr", "de-AT" to "de", "ja-JP" to "ja",
            "ko-KR" to "ko", "zh" to "zh-Hans", "zh-CN" to "zh-Hans", "zh-TW" to "zh-Hant",
            "zh-HK" to "zh-Hant", "zh-MO" to "zh-Hant", "zh-Hans-TW" to "zh-Hans",
            "zh-Hant-CN" to "zh-Hant", "pt" to "pt-BR", "pt-AO" to "pt-BR", "pt-PT" to "pt-PT",
            "es-MX" to "es", "ar-EG" to "ar")) assertEquals(expected, AppLanguage.match(source))
        assertNull(AppLanguage.match("ru-RU"))
        assertNull(AppLanguage.match("und"))
    }
}
