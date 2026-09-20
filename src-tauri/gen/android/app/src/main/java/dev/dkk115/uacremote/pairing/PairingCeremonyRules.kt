// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.pairing

import dev.dkk115.uacremote.R
import dev.dkk115.uacremote.nativecore.NativeCeremonyFailure
import dev.dkk115.uacremote.nativecore.NativeCeremonyPhase

/** Presentation and scheduling constants only; native status owns enrollment. */
internal object PairingCeremonyRules {
    const val POLL_INTERVAL_MILLIS = 250L
    const val MAX_POLLS = 1300

    fun state(phase: NativeCeremonyPhase): PairingScannerState = when (phase) {
        NativeCeremonyPhase.CREATING_KEYS, NativeCeremonyPhase.CONNECTING,
        NativeCeremonyPhase.SUBMITTING, NativeCeremonyPhase.AWAITING_CANDIDATE -> PairingScannerState.CONNECTING
        NativeCeremonyPhase.COMPARE -> PairingScannerState.COMPARE
        NativeCeremonyPhase.AWAITING_ACCEPTANCE -> PairingScannerState.WAITING_PC
        NativeCeremonyPhase.ENROLLED -> PairingScannerState.ENROLLED
        NativeCeremonyPhase.FAILED -> PairingScannerState.FAILED
    }

    fun failureDetail(failure: NativeCeremonyFailure?): Int = when (failure) {
        NativeCeremonyFailure.CANCELLED -> R.string.pairing_scanner_failed_cancelled
        NativeCeremonyFailure.EXPIRED -> R.string.pairing_scanner_failed_expired
        NativeCeremonyFailure.NETWORK -> R.string.pairing_scanner_failed_network
        NativeCeremonyFailure.REJECTED -> R.string.pairing_scanner_failed_rejected
        NativeCeremonyFailure.MISMATCH -> R.string.pairing_scanner_failed_mismatch
        NativeCeremonyFailure.STORAGE -> R.string.pairing_scanner_failed_storage
        NativeCeremonyFailure.UNAVAILABLE, null -> R.string.pairing_scanner_failed_unavailable
    }

    fun terminal(state: PairingScannerState): Boolean =
        state == PairingScannerState.ENROLLED || state == PairingScannerState.FAILED
}
