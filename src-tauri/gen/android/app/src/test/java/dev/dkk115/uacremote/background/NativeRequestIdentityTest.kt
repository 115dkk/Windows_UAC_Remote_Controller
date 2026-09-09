// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.background

import dev.dkk115.uacremote.nativecore.NativeRequestSelection
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class NativeRequestIdentityTest {
    private fun selection() = NativeRequestSelection(ByteArray(32) { 1 }, ByteArray(32) { 2 }, ByteArray(32) { 3 })

    @Test fun withdrawalIdentityCopiesEveryPartAndDoesNotFollowCallerMutation() {
        val original = selection()
        val copied = NativeRequestIdentity.copy(original)
        assertNotNull(copied)
        checkNotNull(copied)
        assertTrue(NativeRequestIdentity.same(original, copied))
        original.request[31] = 4
        assertFalse(NativeRequestIdentity.same(original, copied))
        assertEquals(202, NativeRequestIdentity.notificationTag(copied).length)
        assertTrue(NativeRequestIdentity.notificationTag(copied).startsWith("request:0101"))
        assertTrue(NativeRequestIdentity.notificationTag(copied).endsWith("0303"))
    }

    @Test fun invalidLengthsAndZeroIdentifiersNeverBecomeNotificationTags() {
        for (length in listOf(0, 31, 33, 4096)) {
            val invalid = NativeRequestSelection(ByteArray(length) { 1 }, ByteArray(32) { 2 }, ByteArray(32) { 3 })
            assertNull(NativeRequestIdentity.copy(invalid))
        }
        assertNull(NativeRequestIdentity.copy(NativeRequestSelection(ByteArray(32), ByteArray(32) { 2 }, ByteArray(32) { 3 })))
    }
}
