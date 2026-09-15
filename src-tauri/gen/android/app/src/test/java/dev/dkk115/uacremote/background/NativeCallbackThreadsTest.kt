// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.background

import com.sun.jna.Callback
import org.junit.Assert.assertEquals
import org.junit.Test

/** Synthetic holders and a recording registration only. The generated vtable,
 * the JNA dispatch library and the Rust controller are never loaded here, so
 * this JVM test observes the reflection walk and nothing native. */
class NativeCallbackThreadsTest {
    private class FakeCallback : Callback
    private class FakeVtable {
        @JvmField val first: Callback = FakeCallback()
        @JvmField val second: Callback = FakeCallback()
        @JvmField val absent: Callback? = null
        @JvmField val unrelated: String = "not-a-callback"
    }

    @Test fun everyCallbackSlotIsPinnedOnceAndTheEmptyAndForeignSlotsAreSkipped() {
        val vtable = FakeVtable()
        val pinned = ArrayList<Callback>()
        assertEquals(2, NativeCallbackThreads.pin(vtable) { pinned.add(it) })
        assertEquals(setOf(vtable.first, vtable.second), pinned.toSet())
        assertEquals(2, pinned.size)
    }

    @Test fun repeatingTheCallReportsTheSameSlotsInsteadOfGrowingOrRefusing() {
        val vtable = FakeVtable()
        val pinned = ArrayList<Callback>()
        assertEquals(2, NativeCallbackThreads.pin(vtable) { pinned.add(it) })
        assertEquals(2, NativeCallbackThreads.pin(vtable) { pinned.add(it) })
        assertEquals(4, pinned.size)
        assertEquals(setOf(vtable.first, vtable.second), pinned.toSet())
    }

    @Test fun aFailedRegistrationPinsNothingAndCannotEscapeToTheOwner() {
        assertEquals(0, NativeCallbackThreads.pin(FakeVtable()) { throw IllegalStateException("Synthetic registration failure") })
    }

    @Test fun aHolderWhoseFieldsCannotBeReadPinsNothing() {
        // The JDK refuses to open java.lang.Class to this module, so the walk
        // fails inside reflection instead of reporting a partial count. Where a
        // runtime does open it, a Class holds no callback slot either.
        assertEquals(0, NativeCallbackThreads.pin(FakeVtable::class.java) { throw AssertionError("No slot exists here") })
    }
}
