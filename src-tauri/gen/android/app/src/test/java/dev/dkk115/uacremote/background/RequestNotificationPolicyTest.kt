// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.background

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Pure mode/copy DTO assertions, not Android rendering or audible-alert proof. */
class RequestNotificationPolicyTest {
    @Test fun OnlyFirstFreshAttemptMayRequestAnAlert() {
        assertFalse(RequestNotificationPolicy.quiet(true, false))
        assertTrue(RequestNotificationPolicy.quiet(true, true))
        assertTrue(RequestNotificationPolicy.quiet(false, false)) // Cold Restore.
        assertTrue(RequestNotificationPolicy.quiet(false, true)) // Update.
    }
    @Test fun RestoreAndSilentModeAlwaysRequestSilence() {
        for (mode in RequestNotificationMode.values()) assertTrue(RequestNotificationPolicy.silent(true, mode))
        assertTrue(RequestNotificationPolicy.silent(false, RequestNotificationMode.SILENT))
        assertFalse(RequestNotificationPolicy.silent(false, RequestNotificationMode.SOUND))
        assertFalse(RequestNotificationPolicy.silent(false, RequestNotificationMode.VIBRATION_ONLY))
    }
    @Test fun ChannelIdentitiesDoNotChangeToOverrideUserSettings() {
        assertEquals("uac_requests_sound_v1", RequestNotificationRenderer.channel(RequestNotificationMode.SOUND))
        assertEquals("uac_requests_vibration_v1", RequestNotificationRenderer.channel(RequestNotificationMode.VIBRATION_ONLY))
        assertEquals("uac_requests_silent_v1", RequestNotificationRenderer.channel(RequestNotificationMode.SILENT))
        assertFalse(RequestNotificationRenderer.ownsChannel("controller_service_status_v1"))
    }
    @Test fun HostileLookingPreviewIsRetainedAsPlainTextAndDebugIsRedacted() {
        val program = "<script>synthetic</script>"
        val path = "C:\\synthetic\\אבג\\실행 파일.exe"
        val content = RequestNotificationContent(program, path, false, false)
        assertEquals(program, content.program); assertEquals(path, content.path)
        assertFalse(content.toString().contains(program)); assertFalse(content.toString().contains(path))
    }
    @Test(expected = IllegalArgumentException::class) fun OversizedPreviewCannotReachRenderer() {
        RequestNotificationContent("x".repeat(513), "synthetic.exe", false, false)
    }
}
