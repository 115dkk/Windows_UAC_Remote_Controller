// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.background

import org.junit.Assert.*
import org.junit.Test

/** The record's shape only. Not proof that any callback throws or does not. */
class NativeThrowTraceTest {
    private fun thrown(): Throwable = try { error("synthetic") } catch (failure: Throwable) { failure }

    @Test fun theRecordNamesTheSiteTheFrameAndTheKindAndNeverTheMessage() {
        val failure = thrown()
        val line = requireNotNull(NativeThrowTrace.line("PUBLISH_PENDING_REQUEST", failure))
        assertTrue(line, line.startsWith("UAC_NATIVE_THROW_V1 site=PUBLISH_PENDING_REQUEST at="))
        assertTrue(line, line.contains("NativeThrowTraceTest.thrown:"))
        // Three frames at most, so one framework throw still shows our caller.
        assertTrue(line, line.substringAfter("at=").substringBefore(" kind=").split("|").size <= 3)
        assertTrue(line, line.endsWith("kind=IllegalStateException"))
        // The payload is the one thing that can carry a value, so it stays out.
        assertFalse(line, line.contains("synthetic"))
    }

    @Test fun aRecordThatWouldNotSurviveTheKeyValueShapeIsDroppedRatherThanWidened() {
        val failure = thrown()
        for (hostile in listOf("", "site with spaces", "site=equals", "한글", "x".repeat(49))) {
            assertNull(hostile, NativeThrowTrace.line(hostile, failure))
        }
    }

    @Test fun aThrowableWithoutUsableFramesStillNamesTheSiteAndTheKind() {
        val failure = thrown()
        failure.stackTrace = emptyArray()
        val line = requireNotNull(NativeThrowTrace.line("CLOCK", failure))
        assertEquals("UAC_NATIVE_THROW_V1 site=CLOCK at=unknown kind=IllegalStateException", line)
    }

    @Test fun aMeasurementCarriesItsNumberAndRefusesAnythingOutsideTheClosedShape() {
        assertEquals(
            "UAC_NATIVE_VALUE_V1 site=NOTIFICATION_REMAINING name=millis value=1789642719503",
            NativeThrowTrace.measurementLine("NOTIFICATION_REMAINING", "millis", 1789642719503L),
        )
        assertEquals(
            "UAC_NATIVE_VALUE_V1 site=A name=b value=-1",
            NativeThrowTrace.measurementLine("A", "b", -1L),
        )
        assertNull(NativeThrowTrace.measurementLine("has space", "millis", 1L))
        assertNull(NativeThrowTrace.measurementLine("SITE", "has space", 1L))
        assertNull(NativeThrowTrace.measurementLine("SITE", "x".repeat(33), 1L))
    }

    @Test fun theBlockResultAndTheFailureBothPassThroughUntouched() {
        assertEquals(7, NativeThrowTrace.named("CLOCK") { 7 })
        val raised = IllegalArgumentException("kept")
        val caught = try {
            NativeThrowTrace.named("CLOCK") { throw raised }
        } catch (failure: Throwable) {
            failure
        }
        assertSame(raised, caught)
    }
}
