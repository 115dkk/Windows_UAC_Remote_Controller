// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.background

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Synthetic transitions only; no Android notification posting or PC prompt. */
class ParkedPromptNotificationStateTest {
    @Test fun OnlyTheFirstPositiveObservationAttemptsANotification() {
        val state = ParkedPromptNotificationState()
        assertFalse(state.observe(0, true))
        assertTrue(state.observe(1, true))
        assertFalse(state.observe(1, true))
        assertFalse(state.observe(16, true))
        assertFalse(state.observe(2, true))
        // A blocked or dismissed attempt is not repeated on later catalogues.
        assertFalse(state.observe(2, true))
        assertFalse(state.observe(0, true))
        assertTrue(state.observe(2, true))
    }
    @Test fun DisconnectAndCleanupResetTheWaitingEpisode() {
        val state = ParkedPromptNotificationState()
        assertTrue(state.observe(1, true))
        assertFalse(state.observe(1, false))
        assertTrue(state.observe(1, true))
        state.clear()
        assertTrue(state.observe(16, true))
    }
    @Test fun InvalidCountsNeverPost() {
        val state = ParkedPromptNotificationState()
        for (count in listOf(-1, 0, 17, 255)) assertFalse(state.observe(count, true))
        assertFalse(state.observe(1, false))
        assertTrue(state.observe(1, true))
    }
}
