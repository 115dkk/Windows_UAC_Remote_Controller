// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.background

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Pure synthetic state/argument fixtures, not Android Service/PM/CE evidence. */
class ControllerServiceControlPolicyTest {
    private fun stopped() = ControllerServiceFacts(
        component = BootComponentState.ENABLED,
        reportedState = ControllerServiceState.STOPPED,
        wanted = false, attached = false, startPending = false, phase = null,
        constructionUncertain = false, startRejected = false, generationAvailable = true,
    )
    private fun ready() = stopped().copy(wanted = true, attached = true,
        phase = PolicyOwnerPhase.READY, reportedState = ControllerServiceState.LOCAL_SETTINGS_READY)
    private fun view(facts: ControllerServiceFacts, foreground: Boolean = true) =
        BootServicePolicy.serviceObservation(facts, foreground)

    @Test fun unknownPackageManagerIsNotDisabledAndStillPermitsBestEffortForegroundStop() {
        val value = view(stopped().copy(component = BootComponentState.UNAVAILABLE))
        assertEquals(ControllerServiceState.UNAVAILABLE, value.state)
        assertNull(value.bootEnabled)
        assertFalse(value.canStart)
        assertTrue(value.canStop)
        assertFalse(value.policyOwnerReady)
        assertFalse(view(stopped().copy(component = BootComponentState.UNAVAILABLE), false).canStop)
    }

    @Test fun disabledAndFullyStoppedOffersOnlyExplicitStart() {
        val value = view(stopped().copy(component = BootComponentState.DISABLED))
        assertEquals(ControllerServiceState.STOPPED, value.state)
        assertEquals(false, value.bootEnabled)
        assertTrue(value.canStart)
        assertFalse(value.canStop)
        assertFalse(value.policyOwnerReady)
        assertTrue(view(stopped()).canStop) // Disabling enabled future boot is useful.
    }

    @Test fun readinessRequiresTheActualWantedAttachedReadyOwner() {
        assertTrue(view(ready()).policyOwnerReady)
        for (facts in listOf(
            ready().copy(wanted = false), ready().copy(attached = false),
            ready().copy(phase = null), ready().copy(phase = PolicyOwnerPhase.STARTING),
            ready().copy(startRejected = true), ready().copy(constructionUncertain = true),
            ready().copy(component = BootComponentState.UNAVAILABLE),
        )) assertFalse(view(facts).policyOwnerReady)
        val background = view(ready(), false)
        assertTrue(background.policyOwnerReady) // Observation is not foreground permission.
        assertFalse(background.canStart)
        assertFalse(background.canStop)
    }

    @Test fun noActiveOrUncertainOwnerCanBeStartedAgain() {
        for (phase in listOf(PolicyOwnerPhase.NEW, PolicyOwnerPhase.STARTING,
            PolicyOwnerPhase.READY, PolicyOwnerPhase.FAILED, PolicyOwnerPhase.STOPPING)) {
            assertFalse(view(stopped().copy(phase = phase,
                reportedState = ControllerServiceState.UNAVAILABLE)).canStart)
        }
        assertFalse(view(stopped().copy(constructionUncertain = true)).canStart)
        assertTrue(view(stopped().copy(startRejected = true,
            reportedState = ControllerServiceState.UNAVAILABLE, phase = PolicyOwnerPhase.CLOSED)).canStart)
    }

    @Test fun attachedServiceRemainsCleanupPendingEvenAfterActorClosedAndStopAcknowledged() {
        val afterAck = stopped().copy(component = BootComponentState.DISABLED,
            attached = true, phase = PolicyOwnerPhase.CLOSED)
        assertEquals(ControllerServiceState.CLEANUP_PENDING, view(afterAck).state)
        assertFalse(view(afterAck).canStart)
        assertTrue(view(afterAck).canStop)
        val detached = view(afterAck.copy(attached = false))
        assertEquals(ControllerServiceState.STOPPED, detached.state)
        assertTrue(detached.canStart)
    }

    @Test fun waitingForUnlockDoesNotClaimAnActorAndDoesNotPermitAnotherStart() {
        val facts = stopped().copy(wanted = true, attached = true,
            reportedState = ControllerServiceState.WAITING_FOR_UNLOCK)
        val value = view(facts)
        assertEquals(ControllerServiceState.WAITING_FOR_UNLOCK, value.state)
        assertFalse(value.policyOwnerReady)
        assertFalse(value.canStart)
        assertTrue(value.canStop)
    }

    @Test fun stopBeforeCreateUsesNativeAcknowledgmentWithoutWaitingForMissingDestroyCallback() {
        for (ack in NativeStopObservation.entries) {
            val generations = ServiceStartGenerations()
            val old = generations.reserve()!!
            var facts = stopped().copy(startPending = true)
            generations.invalidate() // The explicit stop revokes old intent first.
            assertFalse(view(facts).canStart)
            assertEquals(ControllerServiceState.CLEANUP_PENDING, view(facts).state)
            assertTrue(BootServicePolicy.stopAcknowledgmentClearsPending(generations.current(), true, ack))
            // No onCreate/onDestroy callback in this fixture: the real return
            // of stopService is sufficient to retire the pending-launch flag.
            facts = facts.copy(startPending = false)
            assertTrue(view(facts).canStart)
            val replacement = generations.reserve()!!
            assertNotEquals(old, replacement)
            assertFalse(BootServicePolicy.acceptsStartGeneration(generations.current(), old, null))
            assertTrue(BootServicePolicy.acceptsStartGeneration(generations.current(), replacement, null))
            assertFalse(BootServicePolicy.stopAcknowledgmentClearsPending(generations.current(), true, ack))
        }
    }

    @Test fun staleStartAndOldDestroyCannotOwnANewerGenerationOrDifferentServiceObject() {
        val generations = ServiceStartGenerations()
        val old = generations.reserve()!!
        val oldToken = Any()
        generations.invalidate()
        val current = generations.reserve()!!
        val currentToken = Any()
        assertFalse(BootServicePolicy.acceptsStartGeneration(current, old, null))
        assertFalse(BootServicePolicy.acceptsStartGeneration(current, current, old))
        assertFalse(BootServicePolicy.detachOwnsCurrentGeneration(currentToken, oldToken, current, current, old))
        assertFalse(BootServicePolicy.detachOwnsCurrentGeneration(currentToken, oldToken, current, current, current))
        assertFalse(BootServicePolicy.detachOwnsCurrentGeneration(currentToken, currentToken, current, current, old))
        assertTrue(BootServicePolicy.detachOwnsCurrentGeneration(currentToken, currentToken, current, current, current))
    }

    @Test fun coldStickyRestartCanMintOnlyWithEnabledBootAndNoStopOrUnfinishedOwner() {
        val cold = stopped().copy(component = BootComponentState.DEFAULT, attached = true)
        val generations = ServiceStartGenerations()
        assertNull(generations.current())
        assertTrue(BootServicePolicy.stickyStartAllowed(cold, false, false))
        val current = generations.reserve()!!
        assertTrue(BootServicePolicy.acceptsStartGeneration(generations.current(), current, null))
        for (component in listOf(BootComponentState.DISABLED, BootComponentState.UNAVAILABLE)) {
            assertFalse(BootServicePolicy.stickyStartAllowed(cold.copy(component = component), false, true))
        }
        assertFalse(BootServicePolicy.stickyStartAllowed(cold, true, true))
        assertFalse(BootServicePolicy.stickyStartAllowed(cold.copy(constructionUncertain = true), false, true))
        for (phase in listOf(PolicyOwnerPhase.FAILED, PolicyOwnerPhase.STOPPING)) {
            assertFalse(BootServicePolicy.stickyStartAllowed(cold.copy(phase = phase), false, true))
        }
        assertFalse(BootServicePolicy.stickyStartAllowed(cold.copy(phase = PolicyOwnerPhase.CLOSED), false, false))
        assertTrue(BootServicePolicy.stickyStartAllowed(cold.copy(phase = PolicyOwnerPhase.CLOSED), false, true))
    }

    @Test fun automaticActivityOrBootStartNeverReenablesStoppedOrUnknownState() {
        assertTrue(BootServicePolicy.automaticStartAllowed(stopped(), false, false))
        assertFalse(BootServicePolicy.automaticStartAllowed(stopped(), true, true))
        for (component in listOf(BootComponentState.DISABLED, BootComponentState.UNAVAILABLE)) {
            assertFalse(BootServicePolicy.automaticStartAllowed(stopped().copy(component = component), false, true))
        }
        assertFalse(BootServicePolicy.automaticStartAllowed(stopped().copy(attached = true), false, true))
        assertFalse(BootServicePolicy.automaticStartAllowed(stopped().copy(startPending = true), false, true))
    }

    @Test fun generationExhaustionIsTerminalForNewStartsAndNeverWrapsOrReuses() {
        val generations = ServiceStartGenerations(Long.MAX_VALUE)
        assertEquals(Long.MAX_VALUE, generations.reserve())
        assertFalse(generations.canReserve())
        assertTrue(generations.matches(Long.MAX_VALUE))
        generations.invalidate()
        assertNull(generations.reserve())
        assertFalse(generations.matches(Long.MAX_VALUE))
        assertFalse(generations.matches(0))
        assertFalse(generations.matches(null))
        val exhausted = stopped().copy(generationAvailable = false)
        assertFalse(view(exhausted).canStart)
        assertFalse(BootServicePolicy.stickyStartAllowed(exhausted.copy(attached = true), false, true))
    }

    @Test fun serviceCommandsAcceptOnlyBoundedNoArgumentRepresentations() {
        for (raw in listOf("null", "{}", " \n{}\t", " ".repeat(28) + "null")) {
            assertTrue(BootServicePolicy.acceptsServiceArguments(raw))
        }
        for (raw in listOf("", "[]", "{ }", "{}null", "null\u0000", " ".repeat(29) + "null",
            "{\"action\":\"start\"}", "{\"bootEnabled\":true}", "{\"generation\":1}", "{\"authenticated\":true}")) {
            assertFalse(BootServicePolicy.acceptsServiceArguments(raw))
        }
    }

    @Test fun delayedCommandsExpireAtFiveSecondsAndNeverSurviveClockRegression() {
        assertFalse(BootServicePolicy.serviceCommandExpired(100, 5_099))
        assertTrue(BootServicePolicy.serviceCommandExpired(100, 5_100))
        assertTrue(BootServicePolicy.serviceCommandExpired(100, 99))
        assertTrue(BootServicePolicy.serviceCommandExpired(-1, 0))
        assertTrue(BootServicePolicy.serviceCommandExpired(0, Long.MAX_VALUE))
        assertEquals(setOf("requested", "unavailable", "not_allowed"), ServiceControlResult.entries.map { it.wireValue }.toSet())
        assertEquals(setOf("stopped", "preparing", "waiting_for_unlock", "local_settings_ready", "cleanup_pending", "unavailable"),
            ControllerServiceState.entries.map { it.wireValue }.toSet())
    }
}
