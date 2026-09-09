// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.background

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ApprovalHostLeaseTest {
    @Test fun credentialCoverSuspendsCompletionWithoutDestroyingTheOriginalHost() {
        val host = Any()
        val lease = ApprovalHostLease(host)
        assertTrue(lease.mayComplete(host))
        lease.paused(host)
        assertTrue(lease.isCurrent(host))
        assertFalse(lease.mayComplete(host))
        assertTrue(lease.resumed(host))
        assertTrue(lease.mayComplete(host))
    }

    @Test fun aRecreatedActivityDoesNotInheritAnOldHostLease() {
        val original = Any()
        val replacement = Any()
        val lease = ApprovalHostLease(original)
        assertFalse(lease.isCurrent(replacement))
        assertFalse(lease.resumed(replacement))
        assertFalse(lease.mayComplete(replacement))
        lease.invalidate()
        assertFalse(lease.resumed(original))
        assertFalse(lease.mayComplete(original))
        assertTrue(ApprovalHostLease(replacement).mayComplete(replacement))
    }

    @Test fun equalityDoesNotSubstituteForTheActualHostIdentity() {
        data class Host(val value: Int)
        val original = Host(1)
        val lookalike = Host(1)
        val lease = ApprovalHostLease(original)
        assertFalse(lease.isCurrent(lookalike))
        lease.paused(lookalike)
        assertTrue(lease.mayComplete(original))
    }
}
