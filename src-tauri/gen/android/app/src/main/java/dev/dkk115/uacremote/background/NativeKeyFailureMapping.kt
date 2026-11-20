// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.background

import dev.dkk115.uacremote.nativecore.BridgeException
import dev.dkk115.uacremote.security.KeyStoreOutcome

/** Fixed operation names only; no alias, handle or provider text is admitted. */
internal enum class NativeKeyOperation {
    CREATE_REQUEST,
    CREATE_SET,
    INSPECT_PUBLIC,
    READ_DESCRIPTOR,
    VALIDATE_NAMESPACE,
    REOPEN_SET,
    DISCARD_PREPARED,
    CLOSE_REFERENCES,
}

internal class NativeKeyFailure private constructor(
    val operation: NativeKeyOperation,
    val nativeCode: String,
    val rollbackCode: String,
) {
    fun diagnosticLine(): String = requireNotNull(
        NativeThrowTrace.keyFailureLine(operation.name, nativeCode, rollbackCode),
    )

    fun record() {
        NativeThrowTrace.keyFailure(operation.name, nativeCode, rollbackCode)
    }

    /** The ABI and screen contract stay unchanged; the fixed diagnostic is richer. */
    fun bridgeException(): BridgeException = BridgeException.LocalKeysUnavailable()

    companion object {
        fun from(operation: NativeKeyOperation, failure: KeyStoreOutcome.Failure): NativeKeyFailure =
            NativeKeyFailure(operation, failure.error.name, failure.rollback.name)
    }
}

internal object NativeKeyFailureMapping {
    fun map(operation: NativeKeyOperation, failure: KeyStoreOutcome.Failure): NativeKeyFailure =
        NativeKeyFailure.from(operation, failure)
}
