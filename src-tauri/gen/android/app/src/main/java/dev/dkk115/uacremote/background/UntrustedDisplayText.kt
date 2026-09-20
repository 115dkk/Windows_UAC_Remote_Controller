// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.background

/** Display-only escaping: originals remain owned by the immutable request.
 * BidiFormatter isolates surrounding text but does not sanitize embedded
 * overrides/isolates. Make those controls visible BEFORE applying our own
 * trusted direction boundary. Preserve Arabic letters, ZWJ and ZWNJ.
 * Every original UTF-16 unit is retained or expanded to exactly eight ASCII
 * units, so bounded original fields remain bounded without suffix truncation. */
internal object UntrustedDisplayText {
    // Below NotificationCompat's 5120-unit truncation limit, including wrappers.
    // Oversized display expansions use a details-only notice, never a cut suffix.
    fun fitsNotification(value: String): Boolean = value.length <= 4096

    fun escape(value: String): String {
        require(value.length <= 1024)
        return buildString(value.length) {
            for (character in value) {
                if (character == '\u061c' || character in '\u200e'..'\u200f' ||
                    character in '\u202a'..'\u202e' || character in '\u2066'..'\u206f') {
                    append("[U+")
                    append(character.code.toString(16).uppercase().padStart(4, '0'))
                    append(']')
                } else append(character)
            }
        }
    }
}
