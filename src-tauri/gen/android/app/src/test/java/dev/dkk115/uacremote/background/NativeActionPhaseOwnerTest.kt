// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.background

import org.junit.Assert.*
import org.junit.Test

/** Pure callback-generation checks; no native admission, auth or devices exercised. */
class NativeActionPhaseOwnerTest {
    @Test fun lateApprovalCancellationPreparationAndProgressCannotOwnNewDenial() {
        val owner = NativeActionPhaseOwner()
        val approval = NativeActionGeneration()
        val denial = NativeActionGeneration()
        assertTrue(owner.admitted(approval))
        assertTrue(owner.admitted(denial))
        repeat(3) { assertFalse(owner.owns(approval)) }
        owner.completed(approval) // stale terminal cleanup cannot release denial
        assertTrue(owner.owns(denial))
    }

    @Test fun rejectedOrBusyCandidateNeverReplacesAdmittedGeneration() {
        val owner = NativeActionPhaseOwner()
        val current = NativeActionGeneration()
        val rejected = NativeActionGeneration()
        owner.admitted(current)
        // Production calls admitted only after true / WAITING native admission.
        assertFalse(owner.owns(rejected))
        owner.completed(rejected)
        assertTrue(owner.owns(current))
    }

    @Test fun synchronousUnadmittedCallbackDoesNotChangeExistingPhase() {
        val owner = NativeActionPhaseOwner()
        val current = NativeActionGeneration()
        val rejected = NativeActionGeneration()
        owner.admitted(current)
        var phase = NativeRequestPhase.SENDING
        // The native request can callback synchronously before returning false
        // or BUSY. The candidate is deliberately not published in that path.
        val rejectedCallback = { if (owner.owns(rejected)) phase = NativeRequestPhase.PENDING }
        rejectedCallback()
        assertEquals(NativeRequestPhase.SENDING, phase)
        assertTrue(owner.owns(current))
    }

    @Test fun olderCallbackDuringAdmissionCannotOverwritePublishedNewInitialPhase() {
        val owner = NativeActionPhaseOwner()
        val original = NativeActionGeneration()
        val denial = NativeActionGeneration()
        owner.admitted(original)
        var phase = NativeRequestPhase.AUTHENTICATING
        val oldCallback = { if (owner.owns(original)) phase = NativeRequestPhase.PENDING }
        oldCallback() // Before actual new admission returns: still the old owner.
        assertEquals(NativeRequestPhase.PENDING, phase)
        owner.admitted(denial)
        phase = NativeRequestPhase.WAITING
        oldCallback() // After publication: this callback is now obsolete.
        assertEquals(NativeRequestPhase.WAITING, phase)
    }

    @Test fun terminalGenerationCannotResumeButFreshAdmittedRetryCan() {
        val owner = NativeActionPhaseOwner()
        val first = NativeActionGeneration()
        owner.admitted(first)
        owner.completed(first)
        assertFalse(owner.owns(first))
        val retry = NativeActionGeneration()
        assertTrue(owner.admitted(retry))
        assertTrue(owner.owns(retry))
        assertFalse(owner.owns(first))
    }

    @Test fun retirementCannotBeReopenedByAnyLateCallbackOrAdmission() {
        val owner = NativeActionPhaseOwner()
        val generation = NativeActionGeneration()
        owner.admitted(generation)
        owner.retire()
        assertFalse(owner.owns(generation))
        assertFalse(owner.admitted(NativeActionGeneration()))
    }

    @Test fun replacementTransfersOnlyCurrentRetainedDeliveryNotRetiredEntry() {
        val original = NativeActionPhaseOwner()
        val generation = NativeActionGeneration()
        original.admitted(generation)
        val replacement = original.replaceForDelivery(generation)
        assertFalse(original.owns(generation))
        assertTrue(replacement.owns(generation))
        val newer = NativeActionGeneration()
        replacement.admitted(newer)
        assertFalse(replacement.owns(generation))
        assertTrue(replacement.owns(newer))
    }

    @Test fun supersededOrMissingDeliveryDoesNotTransferPresentationOwnership() {
        val owner = NativeActionPhaseOwner()
        val oldApproval = NativeActionGeneration()
        val denial = NativeActionGeneration()
        owner.admitted(oldApproval)
        owner.admitted(denial)
        val replacement = owner.replaceForDelivery(oldApproval)
        assertFalse(replacement.owns(oldApproval))
        assertFalse(replacement.owns(denial))
        val emptyReplacement = replacement.replaceForDelivery(null)
        assertFalse(emptyReplacement.owns(oldApproval))
    }
}
