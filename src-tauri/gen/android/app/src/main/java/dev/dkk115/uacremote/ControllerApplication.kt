// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote

import android.app.Application
import dev.dkk115.uacremote.background.ApplicationPolicyActor
import dev.dkk115.uacremote.background.PolicyReply
import dev.dkk115.uacremote.background.PolicyStatus

/** ROOT registers this Application in the manifest; Activities never own its controller. */
class ControllerApplication : Application() {
    @Volatile private var policyActor: ApplicationPolicyActor? = null

    override fun onCreate() {
        super.onCreate()
        if (policyActor != null) return
        try {
            val actor = ApplicationPolicyActor(this)
            policyActor = actor
            actor.start()
        } catch (_: Exception) {
            // No fallback runtime or successful default policy is constructed.
            // Preserve any created actor/handle instead of orphaning an owner.
            try { policyActor?.shutdown() } catch (_: Exception) { }
        }
    }

    internal fun readControllerPolicy(callback: (PolicyReply) -> Unit) {
        val actor = policyActor
        if (actor == null) callback(PolicyReply.Failed(PolicyStatus.UNAVAILABLE))
        else actor.readPolicy(callback)
    }

    internal fun saveControllerPolicy(policyJson: String, callback: (PolicyReply) -> Unit) {
        val actor = policyActor
        if (actor == null) callback(PolicyReply.Failed(PolicyStatus.UNAVAILABLE))
        else actor.savePolicy(policyJson, callback)
    }

    /** Only an actual native owner termination may call this; no Activity/exit hook does. */
    internal fun shutdownControllerPolicyOwner() { policyActor?.shutdown() }
}
