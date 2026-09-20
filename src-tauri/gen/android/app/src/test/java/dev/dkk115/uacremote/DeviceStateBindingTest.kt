// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote

import org.junit.Assert.*
import org.junit.Test

/** Pure object-identity/lifetime tests. These are not JNI or device evidence. */
class DeviceStateBindingTest {
    private data class Host(val logicalId: Int)
    private data class View(val logicalId: Int)

    @Test fun actualViewBeforeFacadeConstructionIsRememberedWithoutRenewal() {
        val slot = DeviceStateBindingSlot<Host, View>()
        val host = Host(1); val view = View(1)
        assertNull(slot.current())
        val original = slot.created(host, view)
        assertSame(original, slot.current())
        assertSame(original, slot.created(host, view))
        assertSame(host, original.original()?.first)
        assertSame(view, original.original()?.second)
    }

    @Test fun equalLogicalIdsDoNotIdentifyAReplacementPhysicalView() {
        val slot = DeviceStateBindingSlot<Host, View>()
        val firstHost = Host(7); val firstView = View(7)
        val original = slot.created(firstHost, firstView)
        val newHost = Host(7); val newView = View(7)
        assertEquals(firstHost, newHost); assertEquals(firstView, newView)
        assertFalse(original.matches(newHost, firstView))
        assertFalse(original.matches(firstHost, newView))
        val replacement = slot.created(newHost, newView)
        assertFalse(original.matches(firstHost, firstView))
        assertTrue(replacement.matches(newHost, newView))
        assertNotSame(original, replacement)
    }

    @Test fun queuedWorkKeepsItsOriginalBindingAfterReplacement() {
        val slot = DeviceStateBindingSlot<Host, View>()
        val host = Host(1); val view = View(1)
        val captured = slot.created(host, view)
        val work = { captured.matches(host, view) }
        val nextHost = Host(2); val nextView = View(2)
        val next = slot.created(nextHost, nextView)
        assertFalse(work())
        assertNull(captured.original())
        assertTrue(next.matches(nextHost, nextView))
        assertFalse(next.matches(host, view))
    }

    @Test fun lateOldDestructionCannotClearTheNewBinding() {
        val slot = DeviceStateBindingSlot<Host, View>()
        val firstHost = Host(1); val firstView = View(1)
        val first = slot.created(firstHost, firstView)
        val nextHost = Host(1); val nextView = View(1)
        val next = slot.created(nextHost, nextView)
        assertFalse(slot.destroyed(firstHost))
        assertSame(next, slot.current())
        first.retire()
        assertTrue(next.matches(nextHost, nextView))
        assertTrue(slot.destroyed(nextHost))
        assertNull(slot.current())
        assertFalse(next.matches(nextHost, nextView))
        assertFalse(slot.destroyed(nextHost))
    }

    @Test fun aNewViewOnTheSameHostStillRetiresOldWork() {
        val slot = DeviceStateBindingSlot<Host, View>()
        val host = Host(1); val oldView = View(1); val newView = View(1)
        val old = slot.created(host, oldView)
        val new = slot.created(host, newView)
        assertFalse(old.matches(host, oldView))
        assertFalse(new.matches(host, oldView))
        assertTrue(new.matches(host, newView))
    }
}
