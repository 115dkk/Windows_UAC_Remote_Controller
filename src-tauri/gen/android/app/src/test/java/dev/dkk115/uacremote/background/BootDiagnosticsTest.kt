// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.background

import android.content.Intent
import dev.dkk115.uacremote.nativecore.BridgeException
import java.util.Collections
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Pure formatting/category tests. No Log call, boot or service execution. */
class BootDiagnosticsTest {
    @Test fun nativeBridgeFailuresKeepFixedDistinctCategoriesWithoutChangingTheStatus() {
        val failures = listOf(
            BridgeException.StorageUnavailable() to OwnerFailureCategory.BRIDGE_STORAGE_UNAVAILABLE,
            BridgeException.InvalidPolicy() to OwnerFailureCategory.BRIDGE_INVALID_POLICY,
            BridgeException.LifecycleIntegrationRequired() to OwnerFailureCategory.BRIDGE_LIFECYCLE_INTEGRATION_REQUIRED,
            BridgeException.OwnerFaulted() to OwnerFailureCategory.BRIDGE_OWNER_FAULTED,
            BridgeException.LocalKeysReconciliationRequired() to OwnerFailureCategory.BRIDGE_LOCAL_KEYS_RECONCILIATION_REQUIRED,
            BridgeException.LocalKeysUnavailable() to OwnerFailureCategory.BRIDGE_LOCAL_KEYS_UNAVAILABLE,
            BridgeException.NativeUnavailable() to OwnerFailureCategory.BRIDGE_NATIVE_UNAVAILABLE,
            BridgeException.InvalidObservation() to OwnerFailureCategory.BRIDGE_INVALID_OBSERVATION,
            BridgeException.Busy() to OwnerFailureCategory.BRIDGE_BUSY,
            BridgeException.Closed() to OwnerFailureCategory.BRIDGE_CLOSED,
        )
        assertEquals(failures.size, failures.map { it.second }.toSet().size)
        for ((failure, expected) in failures) {
            val actual = BootDiagnostics.ownerFailureCategory(failure)
            assertEquals(expected, actual)
            val line = OwnerDiagnosticRecord(OwnerDiagnosticEvent.OWNER_FIRST_FAILURE,
                OwnerInitializationStep.OPEN_NATIVE_OWNER, PolicyOwnerPhase.STARTING,
                OwnerFailureOrigin.INIT_EXCEPTION, actual, PolicyStatus.STORAGE_UNAVAILABLE).line()
            assertTrue(line.contains(" owner_category=${expected.name}"))
            assertTrue(line.endsWith(" owner_status=STORAGE_UNAVAILABLE"))
            assertFalse(line.contains("Exception"))
        }
    }

    @Test fun onlyFixedAcceptedBootActionCategoriesCanReachTheRecord() {
        assertEquals(BootDiagnosticAction.LOCKED_BOOT, BootDiagnostics.bootAction(Intent.ACTION_LOCKED_BOOT_COMPLETED))
        assertEquals(BootDiagnosticAction.BOOT, BootDiagnostics.bootAction(Intent.ACTION_BOOT_COMPLETED))
        assertEquals(BootDiagnosticAction.PACKAGE_REPLACED, BootDiagnostics.bootAction(Intent.ACTION_MY_PACKAGE_REPLACED))
        for (untrusted in listOf(null, "", "synthetic-untrusted-action", Intent.ACTION_USER_UNLOCKED)) {
            assertNull(BootDiagnostics.bootAction(untrusted))
        }
    }

    @Test fun everyStageHasBoundedClosedAlphabetMetadataEvenWithAllFieldsPresent() {
        for (stage in BootDiagnosticStage.values()) {
            val line = BootDiagnosticRecord(stage,
                action = BootDiagnosticAction.values().maxByOrNull { it.name.length },
                component = BootComponentState.values().maxByOrNull { it.name.length },
                unlock = UserUnlockObservation.values().maxByOrNull { it.name.length },
                result = ServiceControlResult.values().maxByOrNull { it.name.length },
                failure = BootDiagnosticFailure.values().maxByOrNull { it.name.length },
                admitted = false, sticky = false, generationPresent = false,
                attached = false, promoted = false, keptCurrent = false,
                activation = BootActivationState.values().maxByOrNull { it.name.length },
                activationPending = false, activationUncertain = false).line()
            assertTrue(line.length <= BootDiagnostics.MAX_LINE_CHARS)
            assertTrue(line.matches(Regex("[A-Za-z_= ]+")))
            assertFalse(line.contains('\n'))
            assertFalse(line.contains('\r'))
        }
        assertEquals("stage=APPLICATION_CREATE", BootDiagnosticRecord(BootDiagnosticStage.APPLICATION_CREATE).line())
    }

    @Test fun exceptionMessagesAndClassesAreNotRendered() {
        val syntheticMessage = "synthetic-private-body /synthetic/path extra=untrusted"
        val security = BootDiagnostics.failureCategory(SecurityException(syntheticMessage))
        val other = BootDiagnostics.failureCategory(IllegalStateException(syntheticMessage))
        assertEquals(BootDiagnosticFailure.SECURITY, security)
        assertEquals(BootDiagnosticFailure.OTHER, other)
        for (category in listOf(security, other)) {
            val line = BootDiagnosticRecord(BootDiagnosticStage.START_REQUEST_FAILED, failure = category).line()
            assertFalse(line.contains(syntheticMessage))
            assertFalse(line.contains("Exception"))
            assertFalse(line.contains("synthetic"))
        }
    }

    @Test fun ownerRecordsHaveOnlyBoundedClosedMetadataForEveryFailureOriginAndCategory() {
        for (event in OwnerDiagnosticEvent.values()) {
            for (origin in OwnerFailureOrigin.values()) {
                for (category in OwnerFailureCategory.values()) {
                    val line = OwnerDiagnosticRecord(event, OwnerInitializationStep.OPEN_NATIVE_OWNER,
                        PolicyOwnerPhase.STARTING, origin, category, PolicyStatus.STORAGE_UNAVAILABLE).line()
                    assertTrue(line.length <= BootDiagnostics.MAX_LINE_CHARS)
                    assertTrue(line.matches(Regex("[A-Z_a-z= ]+")))
                    assertFalse(line.contains('\n'))
                    assertFalse(line.contains('\r'))
                }
            }
        }
        assertEquals("stage=OWNER_READY owner_step=READY owner_phase=READY",
            OwnerDiagnosticRecord(OwnerDiagnosticEvent.OWNER_READY, OwnerInitializationStep.READY, PolicyOwnerPhase.READY).line())
    }

    @Test fun ownerCategoryMappingNeverReadsThrowableTextStackOrClassName() {
        val privateText = "synthetic-private-body /synthetic/path extra=untrusted"
        val cases = listOf(
            null to OwnerFailureCategory.NOT_CAPTURED,
            UnsatisfiedLinkError(privateText) to OwnerFailureCategory.LINKAGE,
            ExceptionInInitializerError(privateText) to OwnerFailureCategory.LINKAGE,
            SecurityException(privateText) to OwnerFailureCategory.SECURITY,
            IllegalStateException(privateText) to OwnerFailureCategory.STATE_CHECK,
            RuntimeException(privateText) to OwnerFailureCategory.OTHER,
        )
        for ((failure, expected) in cases) {
            val category = BootDiagnostics.ownerFailureCategory(failure)
            assertEquals(expected, category)
            val line = OwnerDiagnosticRecord(OwnerDiagnosticEvent.OWNER_FIRST_FAILURE,
                OwnerInitializationStep.GENERATED_CONTRACT, PolicyOwnerPhase.STARTING,
                OwnerFailureOrigin.INIT_EXCEPTION, category, PolicyStatus.UNAVAILABLE).line()
            assertFalse(line.contains(privateText))
            assertFalse(line.contains("Exception"))
            assertFalse(line.contains("Error"))
            assertFalse(line.contains("synthetic"))
        }
        val unreadable = object : RuntimeException() {
            override val message: String get() = throw AssertionError("Message must not be inspected")
            override fun toString(): String = throw AssertionError("Throwable must not be formatted")
        }
        assertEquals(OwnerFailureCategory.OTHER, BootDiagnostics.ownerFailureCategory(unreadable))
    }

    @Test fun ownerTraceEmitsAtMostEightEventsWithoutPollingOrDuplicateStages() {
        val events = ArrayList<OwnerDiagnosticRecord>()
        val trace = OwnerBootTrace { events.add(it) }
        for (step in OwnerInitializationStep.values()) {
            repeat(4) { trace.initializing(step) }
        }
        repeat(4) { trace.ready() }
        repeat(4) { trace.failed(OwnerFailureOrigin.REQUEST_MAINTENANCE, OwnerFailureCategory.NOT_CAPTURED,
            PolicyStatus.UNAVAILABLE, PolicyOwnerPhase.READY) }
        repeat(4) { trace.closed() }
        for (step in OwnerInitializationStep.values()) trace.initializing(step)
        trace.ready()
        trace.failed(OwnerFailureOrigin.INIT_WATCHDOG, OwnerFailureCategory.NOT_CAPTURED, PolicyStatus.UNAVAILABLE, PolicyOwnerPhase.CLOSED)
        assertEquals(8, events.size)
        assertEquals(5, events.count { it.event == OwnerDiagnosticEvent.OWNER_INIT_STEP })
        assertEquals(1, events.count { it.event == OwnerDiagnosticEvent.OWNER_READY })
        assertEquals(1, events.count { it.event == OwnerDiagnosticEvent.OWNER_FIRST_FAILURE })
        assertEquals(OwnerFailureOrigin.REQUEST_MAINTENANCE, events.last().origin)
        assertEquals(PolicyOwnerPhase.CLOSED, events.last().phase)
    }

    @Test fun firstTimeoutReasonSurvivesLateOpenExceptionAndCleanupWithoutReady() {
        val events = ArrayList<OwnerDiagnosticRecord>()
        val trace = OwnerBootTrace { events.add(it) }
        trace.initializing(OwnerInitializationStep.QUEUED)
        trace.initializing(OwnerInitializationStep.GENERATED_CONTRACT)
        trace.failed(OwnerFailureOrigin.INIT_WATCHDOG, OwnerFailureCategory.NOT_CAPTURED, PolicyStatus.UNAVAILABLE, PolicyOwnerPhase.STARTING)
        trace.initializing(OwnerInitializationStep.OPEN_NATIVE_OWNER)
        trace.failed(OwnerFailureOrigin.INIT_EXCEPTION, OwnerFailureCategory.LINKAGE, PolicyStatus.STORAGE_UNAVAILABLE, PolicyOwnerPhase.FAILED)
        trace.ready()
        trace.closed()
        assertEquals(4, events.size)
        assertEquals(OwnerInitializationStep.GENERATED_CONTRACT, events.last().step)
        assertEquals(OwnerFailureOrigin.INIT_WATCHDOG, events.last().origin)
        assertEquals(OwnerFailureCategory.NOT_CAPTURED, events.last().category)
        assertEquals(PolicyStatus.UNAVAILABLE, events.last().status)
        assertFalse(events.any { it.event == OwnerDiagnosticEvent.OWNER_READY })
    }

    @Test fun initFailureBeforeControllerReturnCanCloseWithoutInventingReadyOrChangingPolicyBounds() {
        val lifecycle = PolicyOwnerLifecycle()
        val events = ArrayList<OwnerDiagnosticRecord>()
        val trace = OwnerBootTrace { events.add(it) }
        assertTrue(lifecycle.start())
        trace.initializing(OwnerInitializationStep.QUEUED)
        trace.initializing(OwnerInitializationStep.PACKAGED_LIBRARY)
        trace.failed(OwnerFailureOrigin.INIT_EXCEPTION, OwnerFailureCategory.LINKAGE, PolicyStatus.UNAVAILABLE, lifecycle.phase())
        lifecycle.fail(PolicyStatus.UNAVAILABLE)
        assertFalse(lifecycle.initialized(0, 1))
        trace.ready()
        lifecycle.closed(); trace.closed()
        assertEquals(PolicyOwnerPhase.CLOSED, lifecycle.phase())
        assertFalse(events.any { it.event == OwnerDiagnosticEvent.OWNER_READY })
        assertEquals(OwnerInitializationStep.PACKAGED_LIBRARY, events.last().step)
        assertEquals(15_000L, PolicyOwnerBounds.RESPONSE_TIMEOUT_MILLIS)
        assertFalse(PolicyOwnerBounds.responseExpired(0, 14_999))
        assertTrue(PolicyOwnerBounds.responseExpired(0, 15_000))
    }

    @Test fun loggerFailureCannotEscapeOrReplaceTheLatchedFirstFailure() {
        val events = ArrayList<OwnerDiagnosticRecord>()
        val trace = OwnerBootTrace { event ->
            events.add(event)
            if (event.event == OwnerDiagnosticEvent.OWNER_FIRST_FAILURE) throw AssertionError("Synthetic logger failure")
        }
        trace.initializing(OwnerInitializationStep.OPEN_NATIVE_OWNER)
        trace.failed(OwnerFailureOrigin.INIT_COMPLETION, OwnerFailureCategory.NOT_CAPTURED, PolicyStatus.UNAVAILABLE, PolicyOwnerPhase.FAILED)
        trace.failed(OwnerFailureOrigin.CALL_TIMEOUT, OwnerFailureCategory.OTHER, PolicyStatus.STORAGE_UNAVAILABLE, PolicyOwnerPhase.FAILED)
        trace.closed()
        assertEquals(3, events.size)
        assertEquals(OwnerFailureOrigin.INIT_COMPLETION, events.last().origin)
        assertEquals(PolicyStatus.UNAVAILABLE, events.last().status)
    }

    @Test fun simultaneousMainAndWorkerFailuresRetainExactlyOneWholeOriginalRecord() {
        val events = Collections.synchronizedList(ArrayList<OwnerDiagnosticRecord>())
        val trace = OwnerBootTrace { events.add(it) }
        trace.initializing(OwnerInitializationStep.OPEN_NATIVE_OWNER)
        val gate = CountDownLatch(1)
        val done = CountDownLatch(2)
        val failures = listOf(
            OwnerFailureOrigin.INIT_WATCHDOG to OwnerFailureCategory.NOT_CAPTURED,
            OwnerFailureOrigin.INIT_EXCEPTION to OwnerFailureCategory.LINKAGE,
        )
        val workers = failures.map { (origin, category) ->
            Thread {
                try {
                    if (gate.await(2, TimeUnit.SECONDS)) trace.failed(origin, category, PolicyStatus.UNAVAILABLE, PolicyOwnerPhase.STARTING)
                } finally { done.countDown() }
            }.apply { isDaemon = true; start() }
        }
        gate.countDown()
        assertTrue(done.await(5, TimeUnit.SECONDS))
        for (worker in workers) worker.join(1000)
        assertTrue(workers.none { it.isAlive })
        trace.closed()
        val first = events.single { it.event == OwnerDiagnosticEvent.OWNER_FIRST_FAILURE }
        assertTrue(failures.any { it.first == first.origin && it.second == first.category })
        assertEquals(first.origin, events.last().origin)
        assertEquals(first.category, events.last().category)
        assertEquals(first.status, events.last().status)
        assertEquals(OwnerInitializationStep.OPEN_NATIVE_OWNER, events.last().step)
    }

    @Test fun staleStartObservationDoesNotDescribeTheRejectedGenerationAsAdmitted() {
        assertEquals("stage=GENERATION_REJECTED admitted=false generation_present=true kept_current=true",
            BootDiagnosticRecord(BootDiagnosticStage.GENERATION_REJECTED,
                admitted = false, generationPresent = true, keptCurrent = true).line())
    }
}
