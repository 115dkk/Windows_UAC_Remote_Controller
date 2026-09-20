// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.pairing

import dev.dkk115.uacremote.R
import dev.dkk115.uacremote.nativecore.NativeCeremonyFailure
import dev.dkk115.uacremote.nativecore.NativeCeremonyPhase
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Pure mappings only; no controller, native library, device, camera or network. */
class PairingCeremonyRulesTest {
    @Test fun everyNativePhaseMapsToTheOwnedScannerState() {
        val expected = mapOf(
            NativeCeremonyPhase.CREATING_KEYS to PairingScannerState.CONNECTING,
            NativeCeremonyPhase.CONNECTING to PairingScannerState.CONNECTING,
            NativeCeremonyPhase.SUBMITTING to PairingScannerState.CONNECTING,
            NativeCeremonyPhase.AWAITING_CANDIDATE to PairingScannerState.CONNECTING,
            NativeCeremonyPhase.COMPARE to PairingScannerState.COMPARE,
            NativeCeremonyPhase.AWAITING_ACCEPTANCE to PairingScannerState.WAITING_PC,
            NativeCeremonyPhase.ENROLLED to PairingScannerState.ENROLLED,
            NativeCeremonyPhase.FAILED to PairingScannerState.FAILED,
        )
        assertEquals(NativeCeremonyPhase.values().toSet(), expected.keys)
        for ((phase, state) in expected) assertEquals(state, PairingCeremonyRules.state(phase))
    }

    @Test fun everyNativeFailureHasItsOwnConsumerDetailResource() {
        val expected = mapOf(
            NativeCeremonyFailure.CANCELLED to R.string.pairing_scanner_failed_cancelled,
            NativeCeremonyFailure.EXPIRED to R.string.pairing_scanner_failed_expired,
            NativeCeremonyFailure.NETWORK to R.string.pairing_scanner_failed_network,
            NativeCeremonyFailure.REJECTED to R.string.pairing_scanner_failed_rejected,
            NativeCeremonyFailure.MISMATCH to R.string.pairing_scanner_failed_mismatch,
            NativeCeremonyFailure.STORAGE to R.string.pairing_scanner_failed_storage,
            NativeCeremonyFailure.UNAVAILABLE to R.string.pairing_scanner_failed_unavailable,
        )
        assertEquals(NativeCeremonyFailure.values().toSet(), expected.keys)
        for ((failure, detail) in expected) assertEquals(detail, PairingCeremonyRules.failureDetail(failure))
        assertEquals(expected.size, expected.values.toSet().size)
    }

    @Test fun missingFailureUsesUnavailableWithoutInventingAReason() {
        assertEquals(R.string.pairing_scanner_failed_unavailable, PairingCeremonyRules.failureDetail(null))
    }

    @Test fun onlyEnrolledAndFailedAreCeremonyTerminalStates() {
        for (state in PairingScannerState.values()) {
            assertEquals(state == PairingScannerState.ENROLLED || state == PairingScannerState.FAILED,
                PairingCeremonyRules.terminal(state))
        }
        assertFalse(PairingCeremonyRules.terminal(PairingScannerState.READ))
        assertFalse(PairingCeremonyRules.terminal(PairingScannerState.WAITING_PC))
        assertTrue(PairingCeremonyRules.terminal(PairingCeremonyRules.state(NativeCeremonyPhase.ENROLLED)))
        assertTrue(PairingCeremonyRules.terminal(PairingCeremonyRules.state(NativeCeremonyPhase.FAILED)))
    }

    @Test fun pollBudgetCoversTheOriginalFiveMinuteLifetimeWithoutChangingIt() {
        assertEquals(1300, PairingCeremonyRules.MAX_POLLS)
        assertEquals(250L, PairingCeremonyRules.POLL_INTERVAL_MILLIS)
        val budgetMillis = PairingCeremonyRules.MAX_POLLS * PairingCeremonyRules.POLL_INTERVAL_MILLIS
        assertEquals(325_000L, budgetMillis)
        assertEquals(300_000L, PairingScanRules.LIFETIME_MILLIS)
        assertTrue(budgetMillis >= PairingScanRules.LIFETIME_MILLIS)
        assertFalse(PairingScanRules.current(0, budgetMillis))
    }
}
