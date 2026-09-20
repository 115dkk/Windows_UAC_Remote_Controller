// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.background

import dev.dkk115.uacremote.nativecore.BridgeException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RequestActionFailurePolicyTest {
    @Test fun staleAndPresentationRefreshRejectOnlyTheAction() {
        for (failure in listOf(BridgeException.RequestUnavailable(), BridgeException.PresentationRefreshRequired(),
            BridgeException.ApprovalRejected(), BridgeException.DenialRejected(), BridgeException.Busy())) {
            assertTrue(RequestActionFailurePolicy.requestLocal(failure))
            assertFalse(RequestActionFailurePolicy.approvalRetiresOwner(failure))
        }
    }

    @Test fun durableNativeAndKeyAmbiguityStillRetireTheOwner() {
        for (failure in listOf(BridgeException.Closed(), BridgeException.OwnerFaulted(),
            BridgeException.StorageUnavailable(), BridgeException.NativeUnavailable(),
            BridgeException.InvalidObservation(), BridgeException.LocalKeysUnavailable(),
            BridgeException.LocalKeysReconciliationRequired())) {
            assertFalse(RequestActionFailurePolicy.requestLocal(failure))
            assertTrue(RequestActionFailurePolicy.approvalRetiresOwner(failure))
        }
    }

    @Test fun requestLocalClassificationCannotReleaseUncertainApprovalCleanup() {
        assertTrue(RequestActionFailurePolicy.approvalCleanupRetiresOwner(BridgeException.PresentationRefreshRequired()))
        assertTrue(RequestActionFailurePolicy.approvalCleanupRetiresOwner(BridgeException.RequestUnavailable()))
        assertTrue(RequestActionFailurePolicy.approvalCleanupRetiresOwner(BridgeException.Closed()))
        assertFalse(RequestActionFailurePolicy.approvalCleanupRetiresOwner(BridgeException.Busy()))
    }

    @Test fun rejectedEmptyReserveAndOwnedScopeHaveDifferentCleanup() {
        assertEquals(DenialRejectionCleanup.RELEASE_EMPTY,
            DenialRejectionPolicy.cleanup(true, false, false, false, true))
        assertEquals(DenialRejectionCleanup.SETTLE_ORIGINAL,
            DenialRejectionPolicy.cleanup(false, true, false, false, true))
        assertEquals(DenialRejectionCleanup.SETTLE_ORIGINAL,
            DenialRejectionPolicy.cleanup(false, true, false, true, true))
        assertEquals(DenialRejectionCleanup.RETAIN_FAILED,
            DenialRejectionPolicy.cleanup(false, false, false, false, true))
    }

    @Test fun failedCleanupUnknownNativeInputsAndClosedScopeNeverReleaseAJob() {
        for (hasScope in listOf(false, true)) {
            assertEquals(DenialRejectionCleanup.RETAIN_FAILED,
                DenialRejectionPolicy.cleanup(true, hasScope, false, true, false))
            assertEquals(DenialRejectionCleanup.RETAIN_FAILED,
                DenialRejectionPolicy.cleanup(true, hasScope, true, false, true))
        }
        assertEquals(DenialRejectionCleanup.RETAIN_FAILED,
            DenialRejectionPolicy.cleanup(true, false, false, true, true))
    }
}
