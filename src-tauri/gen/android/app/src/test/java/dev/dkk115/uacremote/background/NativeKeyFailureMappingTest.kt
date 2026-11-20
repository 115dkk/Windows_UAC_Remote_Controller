// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.background

import dev.dkk115.uacremote.nativecore.BridgeException
import dev.dkk115.uacremote.security.DeviceKeyError
import dev.dkk115.uacremote.security.KeyStoreOutcome
import dev.dkk115.uacremote.security.RollbackState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class NativeKeyFailureMappingTest {
    @Test fun keyLossInvalidationPolicyAndProviderFailuresKeepDistinctExistingCodes() {
        val errors = listOf(
            DeviceKeyError.KEY_MISSING,
            DeviceKeyError.KEY_INVALIDATED,
            DeviceKeyError.POLICY_MISMATCH,
            DeviceKeyError.KEYSTORE_UNAVAILABLE,
        )
        val mapped = errors.map { error ->
            NativeKeyFailureMapping.map(
                NativeKeyOperation.REOPEN_SET,
                KeyStoreOutcome.Failure(error),
            )
        }

        assertEquals(errors.map { it.name }, mapped.map { it.nativeCode })
        assertEquals(mapped.size, mapped.map { it.nativeCode }.toSet().size)
        assertTrue(mapped.all { it.bridgeException() is BridgeException.LocalKeysUnavailable })
    }

    @Test fun rollbackClassificationSurvivesTheSameAbiConversion() {
        val complete = NativeKeyFailureMapping.map(
            NativeKeyOperation.CREATE_SET,
            KeyStoreOutcome.Failure(DeviceKeyError.CREATION_FAILED, RollbackState.COMPLETE),
        )
        val uncertain = NativeKeyFailureMapping.map(
            NativeKeyOperation.CREATE_SET,
            KeyStoreOutcome.Failure(DeviceKeyError.CREATION_FAILED, RollbackState.UNCERTAIN),
        )

        assertEquals("COMPLETE", complete.rollbackCode)
        assertEquals("UNCERTAIN", uncertain.rollbackCode)
        assertNotEquals(complete.diagnosticLine(), uncertain.diagnosticLine())
    }

    @Test fun theDiagnosticContainsOnlyFixedOperationAndExistingCodeTokens() {
        val mapped = NativeKeyFailureMapping.map(
            NativeKeyOperation.DISCARD_PREPARED,
            KeyStoreOutcome.Failure(DeviceKeyError.NAMESPACE_MISMATCH, RollbackState.NOT_NEEDED),
        )
        assertEquals(
            "UAC_NATIVE_KEY_FAILURE_V1 operation=DISCARD_PREPARED code=NAMESPACE_MISMATCH rollback=NOT_NEEDED",
            mapped.diagnosticLine(),
        )
    }
}
