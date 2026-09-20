// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote

import android.app.Notification
import android.app.PendingIntent
import android.content.Intent
import android.content.res.Configuration
import android.os.LocaleList
import android.text.BidiFormatter
import android.text.TextDirectionHeuristics
import android.view.View
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import dev.dkk115.uacremote.background.UntrustedDisplayText
import dev.dkk115.uacremote.background.RequestNotificationActions
import dev.dkk115.uacremote.background.RequestNotificationContent
import dev.dkk115.uacremote.background.RequestNotificationMode
import dev.dkk115.uacremote.background.RequestNotificationRenderer
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

        // Exercise the production builder, not just a parallel formatting
        // helper. Creating this immutable intent does not launch an Activity
        // or post a notification; its action is synthetic and never sent.
        val target = InstrumentationRegistry.getInstrumentation().targetContext
        val pending = PendingIntent.getActivity(target, 19015,
            Intent(target, MainActivity::class.java).setAction("fixture.i18n.display-only"),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_CANCEL_CURRENT)
        try {
            val content = RequestNotificationContent("تقرير\u202Egpj.exe", "C:\\ملفات\\تقرير\u202Egpj.exe", false, false)
            val actions = RequestNotificationActions(pending, pending, pending, pending)
            val renderer = RequestNotificationRenderer(target)
            val notification = renderer.build(content, RequestNotificationMode.SILENT, true, 1000, actions)
            val localized = AppLanguage.context(target)
            val boundary = BidiFormatter.getInstance(localized.resources.configuration.locales[0])
            val expectedProgram = boundary.unicodeWrap(UntrustedDisplayText.escape(content.program), TextDirectionHeuristics.LTR)
            val expectedPath = boundary.unicodeWrap(UntrustedDisplayText.escape(content.path), TextDirectionHeuristics.LTR)
            assertEquals(expectedProgram, notification.extras.getCharSequence(Notification.EXTRA_TEXT)?.toString())
            assertEquals(localized.getString(R.string.request_notification_summary, expectedProgram, expectedPath),
                notification.extras.getCharSequence(Notification.EXTRA_BIG_TEXT)?.toString())
            assertEquals("تقرير\u202Egpj.exe", content.program)
            assertEquals("C:\\ملفات\\تقرير\u202Egpj.exe", content.path)
            assertEquals(3, notification.actions.size)

            val expanded = RequestNotificationContent("fixture.exe", "\u202E".repeat(1020) + ".exe", false, false)
            val longNotice = renderer.build(expanded, RequestNotificationMode.SILENT, true, 1000, actions)
            assertEquals(2, longNotice.actions.size)
            assertEquals(localized.getString(R.string.request_action_deny), longNotice.actions[0].title.toString())
            assertEquals(localized.getString(R.string.request_action_details), longNotice.actions[1].title.toString())
            for ((programElided, pathElided) in listOf(true to false, false to true, true to true)) {
                val prefix = RequestNotificationContent("fixture-prefix", "C:\\prefix", programElided, pathElided)
                val notice = renderer.build(prefix, RequestNotificationMode.SILENT, true, 1000, actions)
                assertEquals(2, notice.actions.size)
                assertEquals(localized.getString(R.string.request_notification_public_body),
                    notice.extras.getCharSequence(Notification.EXTRA_BIG_TEXT)?.toString())
                assertEquals(localized.getString(R.string.request_action_deny), notice.actions[0].title.toString())
                assertEquals(localized.getString(R.string.request_action_details), notice.actions[1].title.toString())
            }
        } finally { pending.cancel() }
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
