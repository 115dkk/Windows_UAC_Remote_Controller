// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote

import android.content.res.Configuration
import android.os.LocaleList
import android.text.BidiFormatter
import android.text.TextDirectionHeuristics
import android.view.View
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import dev.dkk115.uacremote.background.UntrustedDisplayText
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.util.Locale

/** Real Android resource/bidi contracts, synthetic strings only. No key, request,
 * camera, approval, service or language-preference mutation is performed. */
@RunWith(AndroidJUnit4::class)
class LanguagePresentationInstrumentationTest {
    @Test fun androidBidiFormatterAloneDoesNotNeutralizeAnEmbeddedOverride() {
        val raw = "report\u202Egpj.exe"
        val formatter = BidiFormatter.getInstance(Locale.forLanguageTag("ar"))
        assertTrue(formatter.unicodeWrap(raw).contains('\u202e'))
        val escaped = UntrustedDisplayText.escape(raw)
        val shown = formatter.unicodeWrap(escaped, TextDirectionHeuristics.LTR)
        assertFalse(shown.contains('\u202e'))
        assertTrue(shown.contains("report[U+202E]gpj.exe"))
        assertEquals("report\u202Egpj.exe", raw)
    }

    @Test fun everySupportedLocaleLoadsNativeCopyAndOnlyArabicIsRtl() {
        val target = InstrumentationRegistry.getInstrumentation().targetContext
        val titles = mutableSetOf<String>()
        for (tag in AppLanguage.supported) {
            val locale = Locale.forLanguageTag(tag)
            val configuration = Configuration(target.resources.configuration).apply {
                setLocales(LocaleList(locale)); setLayoutDirection(locale)
            }
            val localized = target.createConfigurationContext(configuration)
            val title = localized.getString(R.string.pairing_scanner_title)
            assertTrue(title.isNotBlank())
            titles.add(title)
            assertEquals(if (tag == "ar") View.LAYOUT_DIRECTION_RTL else View.LAYOUT_DIRECTION_LTR,
                localized.resources.configuration.layoutDirection)
            for (id in listOf(R.string.approval_auth_title, R.string.approval_auth_description,
                R.string.controller_service_locked, R.string.request_action_approve,
                R.string.pairing_scanner_compare, R.string.pairing_scanner_failed_mismatch)) {
                assertTrue(localized.getString(id).isNotBlank())
            }
            assertEquals(10, localized.getString(R.string.pairing_digit_names).split(',').size)
        }
        // The two Portuguese variants have intentionally different scanner titles.
        assertEquals(AppLanguage.supported.size, titles.size)
    }
}
