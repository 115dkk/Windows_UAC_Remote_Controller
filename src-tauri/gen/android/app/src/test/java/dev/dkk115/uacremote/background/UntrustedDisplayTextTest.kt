// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.background

import org.junit.Assert.*
import org.junit.Test

class UntrustedDisplayTextTest {
    @Test fun maliciousDirectionControlsBecomeVisibleWithoutChangingOriginal() {
        val original = "report\u202Egpj.exe"
        assertEquals("report[U+202E]gpj.exe", UntrustedDisplayText.escape(original))
        assertEquals("report\u202Egpj.exe", original)
        assertEquals("[U+2066]name[U+2069].exe", UntrustedDisplayText.escape("\u2066name\u2069.exe"))
    }

    @Test fun everyBidiAndDeprecatedFormattingControlIsEscaped() {
        val controls = listOf('\u061c', '\u200e', '\u200f') + ('\u202a'..'\u202e') + ('\u2066'..'\u206f')
        for (control in controls) {
            val escaped = UntrustedDisplayText.escape(control.toString())
            assertEquals(8, escaped.length)
            assertFalse(escaped.contains(control))
            assertTrue(escaped.startsWith("[U+") && escaped.endsWith("]"))
        }
    }

    @Test fun legitimateArabicAndJoiningCharactersRemainIntact() {
        val path = "C:\\ملفات\\تقرير\u200c\u200d.exe"
        assertEquals(path, UntrustedDisplayText.escape(path))
        assertEquals("工具-日本語-한국어.exe", UntrustedDisplayText.escape("工具-日本語-한국어.exe"))
    }

    @Test fun maximalExpansionDoesNotDropFilenameSuffix() {
        val original = "\u202e".repeat(1020) + ".exe"
        val escaped = UntrustedDisplayText.escape(original)
        assertEquals(8164, escaped.length)
        assertTrue(escaped.endsWith(".exe"))
        assertFalse(UntrustedDisplayText.fitsNotification(escaped))
        assertTrue(UntrustedDisplayText.fitsNotification("A".repeat(4096)))
        assertFalse(UntrustedDisplayText.fitsNotification("A".repeat(4097)))
    }
}
