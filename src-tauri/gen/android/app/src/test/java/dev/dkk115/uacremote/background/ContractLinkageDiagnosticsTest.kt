// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.background

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ContractLinkageDiagnosticsTest {
    @Test fun nestedChecksumsAreDistinguishedWithoutThrowableText() {
        val error = ExceptionInInitializerError(IllegalStateException("UniFFI API checksum mismatch: SYNTHETIC_PRIVATE_VALUE"))
        val lines = BootDiagnostics.contractLinkageLines(error)
        assertEquals(2, lines.size)
        assertTrue(lines.last().contains("reason=API_CHECKSUM"))
        assertFalse(lines.joinToString().contains("SYNTHETIC_PRIVATE_VALUE"))
        assertTrue(lines.all { it.length <= BootDiagnostics.MAX_LINE_CHARS })
    }
    @Test fun nativeDetailsAreLimitedToPublicCodeLocations() {
        val error = UnsatisfiedLinkError("Unable to load library /private/synthetic 0x123456")
        error.stackTrace = arrayOf(StackTraceElement("com.sun.jna.Native", "register", "/private/synthetic", 12))
        val line = BootDiagnostics.contractLinkageLines(error).single()
        assertTrue(line.contains("kind=UNSATISFIED_LINK reason=LIBRARY_LOAD"))
        assertTrue(line.contains("site=com.sun.jna.Native.register:12"))
        assertFalse(line.contains("/private"))
        assertFalse(line.contains("0x123456"))
    }
}
