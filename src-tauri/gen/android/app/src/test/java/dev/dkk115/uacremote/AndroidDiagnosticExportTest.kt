// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class AndroidDiagnosticExportTest {
    @Test fun persistentStoreAcceptsOnlyClosedBootAndNativeTokens() {
        assertTrue(AndroidDiagnosticStore.persistable("UacBoot", "stage=SERVICE_CREATE"))
        assertTrue(AndroidDiagnosticStore.persistable("UacNative", "UAC_NATIVE_VALUE_V1 site=APPROVAL_RETIRE_BUSY name=waits value=1"))
        assertFalse(AndroidDiagnosticStore.persistable("UacScan", "stage=command argumentBytes=0"))
        assertFalse(AndroidDiagnosticStore.persistable("UacBoot", "request=secret"))
        assertFalse(AndroidDiagnosticStore.persistable("UacBoot", "stage=SERVICE_CREATE request=secret"))
        assertFalse(AndroidDiagnosticStore.persistable("UacNative", "token=secret"))
        assertFalse(AndroidDiagnosticStore.persistable("UacBoot", "stage=BAD\nsecret=value"))
        assertFalse(AndroidDiagnosticStore.persistable("UacBoot", "stage=한글"))
        assertFalse(AndroidDiagnosticStore.persistable("UacBoot", "stage=SECRET"))
        assertFalse(AndroidDiagnosticStore.persistable("UacBoot", "stage=SERVICE_CREATE action=SECRET"))
        assertFalse(AndroidDiagnosticStore.persistable("UacNative", "UAC_NATIVE_INTAKE_V1 site=SECRET error=CLOSED"))
        assertFalse(AndroidDiagnosticStore.persistable("UacNative", "UAC_NATIVE_VALUE_V1 site=APPROVAL_RETIRE_BUSY name=secret value=1"))
        assertTrue(AndroidDiagnosticStore.persistable("UacBoot", "stage=CALLBACK_PIN pinned=42"))
        assertTrue(AndroidDiagnosticStore.persistable("UacBoot", "stage=OWNER_READY owner_step=READY owner_phase=READY"))
    }

    @Test fun storedRecordsRoundTripThroughStrictValidation() {
        val record = AndroidDiagnosticStore.storedRecord(1234, "UacBoot", "stage=SERVICE_CREATE")
        assertNotNull(record)
        assertTrue(AndroidDiagnosticStore.validStoredRecord(record!!.trimEnd()))
        assertFalse(AndroidDiagnosticStore.validStoredRecord("unix_millis=-1 tag=UacBoot stage=SERVICE_CREATE"))
        assertFalse(AndroidDiagnosticStore.validStoredRecord("unix_millis=1 tag=UacBoot request=secret"))
    }

    @Test fun exportDropsMalformedOrUnexpectedLines() {
        val valid = AndroidDiagnosticStore.storedRecord(1234, "UacBoot", "stage=SERVICE_CREATE")!!.trimEnd()
        val bytes = AndroidDiagnosticExporter.render(
            4321, "1.2.3", listOf(valid, "request=secret"),
            listOf("09-21 10:00:00.000 1 2 I UacNative: UAC_NATIVE_VALUE_V1 site=APPROVAL_RETIRE_BUSY name=waits value=1",
                "09-21 10:00:00.000 1 2 I UacNative: request=secret"),
        )
        val text = String(bytes!!, Charsets.UTF_8)
        assertTrue(text.contains("stage=SERVICE_CREATE"))
        assertTrue(text.contains("UAC_NATIVE_VALUE_V1"))
        assertFalse(text.contains("request=secret"))
    }

    @Test fun exportRejectsUnboundedOrInvalidMetadata() {
        assertNull(AndroidDiagnosticExporter.render(-1, "1.0.0", emptyList(), emptyList()))
        assertNull(AndroidDiagnosticExporter.render(1, "bad version", emptyList(), emptyList()))
        val line = AndroidDiagnosticStore.storedRecord(1, "UacBoot", "stage=SERVICE_CREATE")!!.trimEnd()
        assertNull(AndroidDiagnosticExporter.render(1, "1.0.0", List(10_000) { line }, emptyList()))
    }

    @Test fun nativeLogSnapshotRequiresTheClosedNativePrefix() {
        assertFalse(AndroidDiagnosticExporter.validNativeLine("--------- beginning of main"))
        assertFalse(AndroidDiagnosticExporter.validNativeLine("--------- secret"))
        assertTrue(AndroidDiagnosticExporter.validNativeLine("09-21 10:00:00.000 1 2 I UacNative: UAC_NATIVE_PANIC_V1 file=x line=1 column=2 thread=t"))
        assertFalse(AndroidDiagnosticExporter.validNativeLine("09-21 10:00:00.000 1 2 I UacNative: token=secret"))
        assertFalse(AndroidDiagnosticExporter.validNativeLine("09-21 10:00:00.000 1 2 I UacNative: UAC_NATIVE_VALUE_V1 token=secret"))
        assertFalse(AndroidDiagnosticExporter.validNativeLine("09-21 10:00:00.000 1 2 I Other: UAC_NATIVE_VALUE_V1"))
        assertFalse(AndroidDiagnosticExporter.validNativeLine("private-prefix UacNative: UAC_NATIVE_INTAKE_V1 site=CLOCK error=CLOSED"))
        assertFalse(AndroidDiagnosticExporter.validNativeLine("09-21 10:00:00.000 0 2 I UacNative: UAC_NATIVE_INTAKE_V1 site=CLOCK error=CLOSED"))
    }

    @Test fun operationGateHasClosedExactlyOnceFailureTable() {
        var skippedShareCalls = 0
        val unavailable = DiagnosticExportOperationGate().handoff(false, true) { skippedShareCalls += 1; true }
        assertEquals(DiagnosticExportOutcome.UNAVAILABLE, unavailable.outcome)
        assertFalse(unavailable.deleteDocument)

        val background = DiagnosticExportOperationGate().handoff(true, false) { skippedShareCalls += 1; true }
        assertEquals(DiagnosticExportOutcome.UNAVAILABLE, background.outcome)
        assertTrue(background.deleteDocument)
        assertEquals(0, skippedShareCalls)

        val refused = DiagnosticExportOperationGate().handoff(true, true) { false }
        assertEquals(DiagnosticExportOutcome.UNAVAILABLE, refused.outcome)
        assertTrue(refused.deleteDocument)

        val sharedGate = DiagnosticExportOperationGate()
        val shared = sharedGate.handoff(true, true) { true }
        assertEquals(DiagnosticExportOutcome.SHARED, shared.outcome)
        assertFalse(shared.deleteDocument)
        assertNull(sharedGate.timeout())

        val timedOut = DiagnosticExportOperationGate()
        assertEquals(DiagnosticExportOutcome.UNAVAILABLE, timedOut.timeout())
        var lateShareCalls = 0
        val late = timedOut.handoff(true, true) { lateShareCalls += 1; true }
        assertNull(late.outcome)
        assertTrue(late.deleteDocument)
        assertEquals(0, lateShareCalls)
        assertNull(timedOut.timeout())
    }
}
