// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.background

import dev.dkk115.uacremote.AndroidDiagnosticStore

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

    /**
     * One bounded number, for the case where knowing a value is the difference
     * between naming a defect and guessing at it. Durations and counts only:
     * this is the protocol's own timing, the same countdown the request screen
     * already shows, and never a request field.
     */
    internal fun measurement(site: String, name: String, value: Long) {
        val line = measurementLine(site, name, value) ?: return
        try { AndroidDiagnosticStore.record(TAG, line) } catch (_: Throwable) { }
    }

    /** Separate from [measurement] so the formatting is testable. */
    internal fun measurementLine(site: String, name: String, value: Long): String? {
        if (!token(site, 48) || !token(name, 32)) return null
        return "UAC_NATIVE_VALUE_V1 site=$site name=$name value=$value"
    }

    /** Separate from [named] so the formatting is testable without throwing. */
    internal fun note(site: String, failure: Throwable) {
        val line = line(site, failure) ?: return
        try { AndroidDiagnosticStore.record(TAG, line) } catch (_: Throwable) { }
    }

    /**
     * Returns the record, or null when any part of it is not the closed shape
     * this is allowed to write. A refused line is dropped rather than widened;
     * a diagnostic is not worth a surprise in what gets logged.
     */
    internal fun line(site: String, failure: Throwable): String? {
        if (!token(site, 48)) return null
        val kind = failure.javaClass.simpleName.takeIf { token(it, 64) } ?: return null
        // Three frames, not one. The first frame is where the throwable was
        // built, which for a framework exception is inside the framework; the
        // next two are what our own code was doing when it asked.
        val frames = runCatching { failure.stackTrace.take(FRAMES) }.getOrNull().orEmpty()
        val at = frames.mapNotNull(::frame).joinToString("|").ifEmpty { "unknown" }
        return "UAC_NATIVE_THROW_V1 site=$site at=$at kind=$kind"
    }

    /** How many frames of the throwable's own stack the record carries. */
    private const val FRAMES = 3

    /** One frame as `Type.method:line`, or null when any part is not a token. */
    private fun frame(element: StackTraceElement): String? {
        val type = element.className.substringAfterLast('.').takeIf { token(it, 64) } ?: return null
        val method = element.methodName.takeIf { token(it, 64) } ?: return null
        return if (element.lineNumber < 0) null else "$type.$method:${element.lineNumber}"
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
