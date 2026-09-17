// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.background

import android.util.Log

/**
 * Names where a platform callback threw, and nothing else.
 *
 * This is not a capability, a key, a store or an authorization step. It reads
 * and writes no request, notification or key material, decides nothing about an
 * approval or a denial, and changes no generated interface. It observes a
 * throwable on its way out and rethrows the same instance.
 *
 * **Why it is needed.** Every unexpected exception a callback throws reaches
 * Rust as one value, `BridgeError::NativeUnavailable`, and UniFFI keeps the
 * throwable to itself on the way. On the request path this class has more than
 * forty sites that raise exactly that, so the native side can say a callback
 * failed and never which one. Rather than edit forty throw statements, this
 * reads the site off the throwable's own first stack frame, which is where it
 * was constructed.
 *
 * **What it records.** A fixed site token, the declaring class, the method, the
 * line, and the throwable's simple class name. Every one of those is an
 * identifier the compiler wrote. The message is never read: a message is prose
 * an author can interpolate a value into, and the values near here are requests
 * and selections.
 */
internal object NativeThrowTrace {
    private const val TAG = "UacNative"

    /**
     * Runs [block], and if it throws, records where before letting the same
     * throwable continue. The result and the failure are both passed through
     * untouched, so wrapping a callback cannot change what Rust receives.
     */
    internal inline fun <T> named(site: String, block: () -> T): T =
        try {
            block()
        } catch (failure: Throwable) {
            note(site, failure)
            throw failure
        }

    /** Separate from [named] so the formatting is testable without throwing. */
    internal fun note(site: String, failure: Throwable) {
        val line = line(site, failure) ?: return
        try { Log.i(TAG, line) } catch (_: Throwable) { }
    }

    /**
     * Returns the record, or null when any part of it is not the closed shape
     * this is allowed to write. A refused line is dropped rather than widened;
     * a diagnostic is not worth a surprise in what gets logged.
     */
    internal fun line(site: String, failure: Throwable): String? {
        if (!token(site, 48)) return null
        val kind = failure.javaClass.simpleName.takeIf { token(it, 64) } ?: return null
        val frame = runCatching { failure.stackTrace.firstOrNull() }.getOrNull()
        val at = frame?.let {
            val type = it.className.substringAfterLast('.').takeIf { name -> token(name, 64) }
            val method = it.methodName.takeIf { name -> token(name, 64) }
            if (type == null || method == null || it.lineNumber < 0) null else "$type.$method:${it.lineNumber}"
        } ?: "unknown"
        return "UAC_NATIVE_THROW_V1 site=$site at=$at kind=$kind"
    }

    /**
     * Identifiers only. Obfuscation can rename a class to something short, and
     * a synthetic frame can carry characters a `key=value` line would not
     * survive, so the shape is checked rather than assumed.
     */
    private fun token(value: String, max: Int): Boolean =
        value.isNotEmpty() && value.length <= max &&
            value.all { it.isLetterOrDigit() && it.code < 128 || it == '_' || it == '$' }
}
