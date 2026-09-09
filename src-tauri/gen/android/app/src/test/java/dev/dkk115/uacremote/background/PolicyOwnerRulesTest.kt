// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.background

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Pure synthetic state only; no Application, threads, JNA, files, keys or Android calls. */
class PolicyOwnerRulesTest {
    @Test fun failedShutdownKeepsTheHandleForExplicitCleanupRetryBeforeDestroy() {
        val cleanup = ControllerCleanupState()
        assertEquals(ControllerCleanupAction.SHUTDOWN_THEN_DESTROY, cleanup.next(false))
        cleanup.failed()
        assertEquals(ControllerCleanupAction.NONE, cleanup.next(false))
        assertEquals(ControllerCleanupAction.SHUTDOWN_THEN_DESTROY, cleanup.next(true))
        cleanup.shutdownSucceeded()
        assertEquals(ControllerCleanupAction.DESTROY, cleanup.next(false))
        cleanup.failed()
        assertEquals(ControllerCleanupAction.NONE, cleanup.next(false))
        assertEquals(ControllerCleanupAction.DESTROY, cleanup.next(true))
        cleanup.destroyed()
        assertEquals(ControllerCleanupAction.NONE, cleanup.next(true))
    }

    @Test fun initializationAllowsOnlyEightPendingPolicyCalls() {
        val state = PolicyOwnerLifecycle()
        assertEquals(PolicyStatus.UNAVAILABLE, state.admit())
        assertTrue(state.start())
        assertFalse(state.start())
        repeat(PolicyOwnerBounds.MAX_PENDING) { assertNull(state.admit()) }
        assertEquals(8, state.pendingCount())
        assertEquals(PolicyStatus.BUSY, state.admit())
        assertEquals(8, state.pendingCount())
        assertTrue(state.initialized(0, 0))
        assertEquals(PolicyOwnerPhase.READY, state.phase())
        state.release()
        assertNull(state.admit())
    }

    @Test fun initializationFailureCannotBecomeReadyOrDefaultSettingsLater() {
        val state = PolicyOwnerLifecycle()
        state.start()
        assertNull(state.admit())
        state.fail(PolicyStatus.STORAGE_UNAVAILABLE)
        assertFalse(state.initialized(0, 0))
        assertFalse(state.start())
        assertEquals(PolicyStatus.STORAGE_UNAVAILABLE, state.admit())
        assertEquals(1, state.pendingCount())
        state.release()
        assertEquals(0, state.pendingCount())
        assertEquals(PolicyOwnerPhase.FAILED, state.phase())
    }

    @Test fun timeoutFailureDoesNotReopenAfterQueuedCallsFinish() {
        val state = PolicyOwnerLifecycle()
        state.start()
        state.initialized(0, 0)
        repeat(8) { assertNull(state.admit()) }
        state.fail(PolicyStatus.UNAVAILABLE)
        repeat(8) { state.release() }
        assertEquals(0, state.pendingCount())
        assertEquals(PolicyStatus.UNAVAILABLE, state.admit())
        assertFalse(state.initialized(0, 0))
        assertFalse(state.start())
    }

    @Test fun explicitStopDuringStartupRejectsALateInitialization() {
        val state = PolicyOwnerLifecycle()
        state.start()
        state.stop()
        assertFalse(state.initialized(0, 0))
        assertEquals(PolicyStatus.UNAVAILABLE, state.admit())
        state.closed()
        state.stop()
        state.fail(PolicyStatus.STORAGE_UNAVAILABLE)
        assertEquals(PolicyOwnerPhase.CLOSED, state.phase())
        assertFalse(state.start())
    }

    @Test(expected = IllegalStateException::class)
    fun aDuplicateReleaseCannotUnderflowTheAdmissionBound() {
        PolicyOwnerLifecycle().release()
    }

    @Test fun delayedMainHandlerCannotMakeLateInitializationReady() {
        for (now in listOf(15_000L, 20_000L, -1L)) {
            val state = PolicyOwnerLifecycle()
            state.start()
            assertFalse(state.initialized(0, now))
            assertEquals(PolicyOwnerPhase.FAILED, state.phase())
            assertEquals(PolicyStatus.UNAVAILABLE, state.admit())
            assertFalse(state.initialized(0, 1))
        }
        val timely = PolicyOwnerLifecycle()
        timely.start()
        assertTrue(timely.initialized(0, 14_999))
    }

    @Test fun utf8ByteBoundIsNotACharacterCountOrSchemaValidation() {
        assertFalse(PolicyOwnerBounds.validPolicyString(""))
        assertTrue(PolicyOwnerBounds.validPolicyString("x".repeat(16 * 1024)))
        assertFalse(PolicyOwnerBounds.validPolicyString("x".repeat(16 * 1024 + 1)))
        assertTrue(PolicyOwnerBounds.validPolicyString("가".repeat(5461)))
        assertFalse(PolicyOwnerBounds.validPolicyString("가".repeat(5462)))
        assertTrue(PolicyOwnerBounds.validPolicyString("\uD83D\uDE00".repeat(4096)))
        assertFalse(PolicyOwnerBounds.validPolicyString("\uD83D\uDE00".repeat(4097)))
        // Non-JSON text can pass only the size gate; Rust remains the strict codec.
        assertTrue(PolicyOwnerBounds.validPolicyString("not a JSON policy"))
    }

    @Test fun loneSurrogatesAreNotSilentlyReplacedBeforeRustValidation() {
        for (invalid in listOf("\uD800", "\uDC00", "\uD800a", "a\uDC00")) {
            assertFalse(PolicyOwnerBounds.validPolicyString(invalid))
        }
    }

    @Test fun responseDeadlineRejectsLateOrRegressingObservationsWithoutOverflow() {
        assertFalse(PolicyOwnerBounds.responseExpired(0, 14_999))
        assertTrue(PolicyOwnerBounds.responseExpired(0, 15_000))
        assertTrue(PolicyOwnerBounds.responseExpired(-1, 0))
        assertTrue(PolicyOwnerBounds.responseExpired(1, 0))
        assertFalse(PolicyOwnerBounds.responseExpired(Long.MAX_VALUE - 14_999, Long.MAX_VALUE))
        assertTrue(PolicyOwnerBounds.responseExpired(Long.MAX_VALUE - 15_000, Long.MAX_VALUE))
        assertTrue(PolicyOwnerBounds.responseExpired(0, Long.MAX_VALUE))
    }

    @Test fun libraryLoadingRejectsOverridesAndEvidenceOfPriorJnaLoading() {
        assertTrue(ControllerLibraryPolicy.permitsInitialProperties(emptyList()))
        assertTrue(ControllerLibraryPolicy.permitsInitialProperties(listOf("java.vm.name", "java.library.path")))
        for (name in listOf(
            "jna.library.path", "jna.platform.library.path", "jna.boot.library.path", "jna.boot.library.name",
            "jna.tmpdir", "jna.nounpack", "jna.noclasspath", "jna.loaded", "jnidispatch.path",
            "uniffi.component.uac_android_controller.libraryOverride",
            "uniffi.component.another.libraryOverride", "javawebstart.version",
        )) {
            assertFalse(ControllerLibraryPolicy.permitsInitialProperties(listOf(name)))
        }
        assertEquals("uac_android_controller", ControllerLibraryPolicy.LIBRARY)
        assertEquals(5u, ControllerLibraryPolicy.ABI_VERSION)
    }

    @Test fun loaderPropertyInspectionIsBounded() {
        assertFalse(ControllerLibraryPolicy.permitsInitialProperties(List(1025) { "synthetic.$it" }))
        assertFalse(ControllerLibraryPolicy.permitsInitialProperties(listOf("x".repeat(257))))
        assertFalse(ControllerLibraryPolicy.permitsInitialProperties(listOf("")))
    }

    @Test fun partialControllerAliasesStillPreventFreshBootstrap() {
        assertTrue(ControllerLibraryPolicy.isControllerAlias(PolicyOwnerBounds.KEY_NAMESPACE))
        assertTrue(ControllerLibraryPolicy.isControllerAlias(PolicyOwnerBounds.KEY_NAMESPACE + "synthetic-partial"))
        assertTrue(ControllerLibraryPolicy.isControllerAlias(PolicyOwnerBounds.KEY_NAMESPACE + "a".repeat(64) + ".approval"))
        assertFalse(ControllerLibraryPolicy.isControllerAlias("another.application.key"))
        assertFalse(ControllerLibraryPolicy.isControllerAlias("prefix-" + PolicyOwnerBounds.KEY_NAMESPACE))
        assertEquals(4096, PolicyOwnerBounds.MAX_KEY_ALIASES)
    }

    @Test fun policyResultsUseFixedStatusesAndRedactDocumentDebug() {
        val text = "{\"synthetic\":\"not real policy data\"}"
        assertFalse(PolicyReply.Committed(text).toString().contains(text))
        assertFalse(PolicyReply.HistoryCommitted(text).toString().contains(text))
        assertEquals("busy", PolicyStatus.BUSY.wireValue)
        assertEquals("unavailable", PolicyStatus.UNAVAILABLE.wireValue)
        assertEquals("invalid_policy", PolicyStatus.INVALID_POLICY.wireValue)
        assertEquals("storage_unavailable", PolicyStatus.STORAGE_UNAVAILABLE.wireValue)
        assertEquals("history_unavailable", PolicyStatus.HISTORY_UNAVAILABLE.wireValue)
    }

    @Test fun historyResultSizeHasItsOwnBoundWithoutRelaxingPolicyInput() {
        val largerThanPolicy = "x".repeat(PolicyOwnerBounds.MAX_POLICY_BYTES + 1)
        assertFalse(PolicyOwnerBounds.validPolicyString(largerThanPolicy))
        assertTrue(PolicyOwnerBounds.validHistoryString(largerThanPolicy))
        assertTrue(PolicyOwnerBounds.validHistoryString("x".repeat(PolicyOwnerBounds.MAX_HISTORY_BYTES)))
        assertFalse(PolicyOwnerBounds.validHistoryString("x".repeat(PolicyOwnerBounds.MAX_HISTORY_BYTES + 1)))
        assertFalse(PolicyOwnerBounds.validHistoryString("\uD800"))
    }

    @Test fun constructorFailureRetainsMemoryKeyCleanupUntilAcknowledged() {
        val keys = KeyReferenceCleanupState()
        assertTrue(keys.shouldAttempt(false))
        keys.failed()
        assertFalse(keys.complete())
        assertFalse(keys.shouldAttempt(false))
        assertTrue(keys.shouldAttempt(true))
        keys.failed()
        assertFalse(keys.complete())
        keys.succeeded()
        assertTrue(keys.complete())
        assertFalse(keys.shouldAttempt(false))
        assertFalse(keys.shouldAttempt(true))
        keys.failed()
        assertTrue(keys.complete())
    }
}
