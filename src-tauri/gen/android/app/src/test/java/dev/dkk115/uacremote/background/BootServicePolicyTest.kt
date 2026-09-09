// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.background

import android.content.Intent
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

/** Pure synthetic lifecycle inputs, not actual boot/FGS/CE/framework evidence. */
class BootServicePolicyTest {
    @Test fun manifestDefaultIsEnabledButExplicitDisabledOrUnknownNeverBecomesEnabled() {
        assertTrue(BootServicePolicy.bootEnabled(BootComponentState.DEFAULT))
        assertTrue(BootServicePolicy.bootEnabled(BootComponentState.ENABLED))
        assertFalse(BootServicePolicy.bootEnabled(BootComponentState.DISABLED))
        assertFalse(BootServicePolicy.bootEnabled(BootComponentState.UNAVAILABLE))
    }

    @Test fun onlyThreeSystemBootAndPackageActionsUseTheManifestReceiver() {
        for (action in listOf(Intent.ACTION_LOCKED_BOOT_COMPLETED, Intent.ACTION_BOOT_COMPLETED, Intent.ACTION_MY_PACKAGE_REPLACED)) {
            assertTrue(BootServicePolicy.acceptsBootAction(action))
        }
        for (action in listOf(null, "", "START", Intent.ACTION_USER_UNLOCKED, Intent.ACTION_PACKAGE_REPLACED)) {
            assertFalse(BootServicePolicy.acceptsBootAction(action))
        }
    }

    @Test fun lockedOrUnknownStorageNeverStartsAnyActor() {
        val phases = listOf(null) + PolicyOwnerPhase.values().toList()
        for (phase in phases) {
            assertEquals(BootOwnerAction.WAIT_FOR_UNLOCK,
                BootServicePolicy.ownerAction(UserUnlockObservation.LOCKED, phase, true, false))
            assertEquals(BootOwnerAction.UNAVAILABLE,
                BootServicePolicy.ownerAction(UserUnlockObservation.UNAVAILABLE, phase, true, false))
        }
    }

    @Test fun firstOwnerRequiresActualUnlockAndNoUncertainConstruction() {
        assertEquals(BootOwnerAction.START_NEW,
            BootServicePolicy.ownerAction(UserUnlockObservation.UNLOCKED, null, false, false))
        assertEquals(BootOwnerAction.UNAVAILABLE,
            BootServicePolicy.ownerAction(UserUnlockObservation.UNLOCKED, null, true, true))
    }

    @Test fun repeatedStartsKeepTheSameNewStartingOrReadyActor() {
        for (phase in listOf(PolicyOwnerPhase.NEW, PolicyOwnerPhase.STARTING, PolicyOwnerPhase.READY)) {
            repeat(3) {
                assertEquals(BootOwnerAction.KEEP_EXISTING,
                    BootServicePolicy.ownerAction(UserUnlockObservation.UNLOCKED, phase, true, false))
            }
        }
    }

    @Test fun replacementNeverSkipsActualFailedOrStoppingOwnerCleanup() {
        for (phase in listOf(PolicyOwnerPhase.FAILED, PolicyOwnerPhase.STOPPING)) {
            for (explicitReplacement in listOf(false, true)) {
                assertEquals(BootOwnerAction.WAIT_FOR_CLEANUP,
                    BootServicePolicy.ownerAction(UserUnlockObservation.UNLOCKED, phase, explicitReplacement, false))
            }
        }
        assertEquals(BootOwnerAction.UNAVAILABLE,
            BootServicePolicy.ownerAction(UserUnlockObservation.UNLOCKED, PolicyOwnerPhase.CLOSED, false, false))
        assertEquals(BootOwnerAction.START_NEW,
            BootServicePolicy.ownerAction(UserUnlockObservation.UNLOCKED, PolicyOwnerPhase.CLOSED, true, false))
    }

    @Test fun closedOwnerReplacementStillRequiresFreshUnlockAndConstructionCertainty() {
        assertEquals(BootOwnerAction.WAIT_FOR_UNLOCK,
            BootServicePolicy.ownerAction(UserUnlockObservation.LOCKED, PolicyOwnerPhase.CLOSED, true, false))
        assertEquals(BootOwnerAction.UNAVAILABLE,
            BootServicePolicy.ownerAction(UserUnlockObservation.UNLOCKED, PolicyOwnerPhase.CLOSED, true, true))
    }

    @Test fun preOwnerReadsHaveAFixedEightItemBound() {
        assertEquals(8, BootServicePolicy.MAX_PENDING_READS)
        for (count in 0..7) assertTrue(BootServicePolicy.canQueueRead(count))
        for (count in listOf(-1, 8, 9, Int.MAX_VALUE)) assertFalse(BootServicePolicy.canQueueRead(count))
    }

    @Test fun readWaitDeadlineIsAbsoluteAndClockRegressionExpiresIt() {
        assertFalse(BootServicePolicy.readExpired(100, 100))
        assertFalse(BootServicePolicy.readExpired(100, 5_099))
        assertTrue(BootServicePolicy.readExpired(100, 5_100))
        assertTrue(BootServicePolicy.readExpired(100, 99))
        assertTrue(BootServicePolicy.readExpired(-1, 100))
        assertTrue(BootServicePolicy.readExpired(0, Long.MAX_VALUE))
        assertFalse(BootServicePolicy.readExpired(Long.MAX_VALUE - 10, Long.MAX_VALUE))
    }

    @Test fun lifecycleTraceClearsOnlyTheExactObservedHostAndNeverTransfersResume() {
        val trace = ResumedHostTrace<Any>()
        val first = Any()
        val replacement = Any()
        assertNull(trace.current())
        trace.resumed(first)
        assertSame(first, trace.current())
        trace.pausedOrDestroyed(replacement)
        assertSame(first, trace.current())
        trace.pausedOrDestroyed(first)
        assertNull(trace.current())
        trace.resumed(replacement)
        trace.pausedOrDestroyed(first)
        assertSame(replacement, trace.current())
        trace.pausedOrDestroyed(replacement)
        assertNull(trace.current())
    }
}
