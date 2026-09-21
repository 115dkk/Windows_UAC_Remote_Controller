// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.background

import dev.dkk115.uacremote.nativecore.NativeOutcomeKind
import dev.dkk115.uacremote.nativecore.NativeOutcomeReceipt
import dev.dkk115.uacremote.AndroidDiagnosticStore
import org.json.JSONArray
import org.json.JSONObject

/** In-process observation identity only; not a request/signing capability. */
internal class NativeDecisionObservation {
    override fun toString(): String = "NativeDecisionObservation([redacted])"
}

/** Body-free, bounded presentation/measurement only; never consulted by an action gate. */
internal class NativeDecisionMeasurements(private val emit: (String) -> Unit = { AndroidDiagnosticStore.record("UacNative", it) }) {
    private class Entry(val locator: String, val action: NativeRequestAction, val ids: List<ByteArray>, val started: Long, val sample: Int, val observation: NativeDecisionObservation) {
        var authenticated: Long? = null
        var submitted: Long? = null
        var received: Long? = null
        var outcome: NativeOutcomeKind? = null
        var phase = if (action == NativeRequestAction.APPROVE) "authenticating" else "preparing"
        var localStopped: Long? = null
        var timingAvailable = false
    }
    private val entries = LinkedHashMap<String, Entry>()
    private val attempts = ArrayList<Entry>()
    private var uncertainUntil = 0L
    private var nextSample = 0

    @Synchronized fun accepted(locator: String, action: NativeRequestAction, ids: List<ByteArray>, now: Long,
                               observation: NativeDecisionObservation = NativeDecisionObservation()): NativeDecisionObservation {
        if (action == NativeRequestAction.DETAILS || now < 0 || ids.size != 7 || ids.any { it.size != 32 }) return observation
        // One sample per accepted choice. Repeated same-choice progress cannot
        // reset its start. An accepted opposite choice starts a fresh sample;
        // its actual PC result may still differ and must be displayed as such.
        if (attempts.any { it.observation === observation }) return observation
        attempts.removeAll { now >= it.started && now - it.started > MAX_NANOS }
        if (attempts.size >= 64) {
            attempts.removeAt(0)
            uncertainUntil = maxOf(uncertainUntil, if (now > Long.MAX_VALUE - MAX_NANOS) Long.MAX_VALUE else now + MAX_NANOS)
        }
        if (entries.size >= 32) entries.remove(entries.keys.first())
        nextSample = if (nextSample == 1_000_000) 1 else nextSample + 1
        val entry = Entry(locator, action, ids.map { it.copyOf() }, now, nextSample, observation)
        entries[locator] = entry; attempts.add(entry)
        return observation
    }

    @Synchronized fun localStatus(locator: String, observation: NativeDecisionObservation, authenticationCancelled: Boolean, now: Long) {
        val entry = current(locator, observation) ?: return
        if (entry.received != null || entry.localStopped != null || now < entry.started || now - entry.started > MAX_NANOS) return
        entry.phase = if (authenticationCancelled) "authentication_cancelled" else "local_unconfirmed"
        entry.localStopped = now
        // Preserve exact expected IDs. A later authenticated PC result is more
        // informative than this local observation and is allowed to supersede it.
    }

    @Synchronized fun progress(locator: String, observation: NativeDecisionObservation, phase: NativeRequestPhase, now: Long) {
        val entry = current(locator, observation) ?: return
        if (entry.received != null || entry.localStopped != null) return
        when (phase) {
            NativeRequestPhase.AUTHENTICATING -> entry.phase = "authenticating"
            NativeRequestPhase.WAITING -> entry.phase = "preparing"
            NativeRequestPhase.SENDING -> entry.phase = "sending"
            NativeRequestPhase.AWAITING_OUTCOME -> entry.phase = "awaiting_pc"
            NativeRequestPhase.PENDING, NativeRequestPhase.UNAVAILABLE -> localStatus(locator, observation, false, now)
        }
    }

    @Synchronized fun prepared(locator: String, observation: NativeDecisionObservation, authenticated: Long?, submitted: Long) {
        val entry = current(locator, observation) ?: return
        if (entry.received != null || entry.localStopped != null || submitted < entry.started) return
        if (entry.action == NativeRequestAction.DENY && authenticated != null) return
        if (authenticated != null && authenticated in entry.started..submitted) entry.authenticated = authenticated
        if (entry.submitted == null) entry.submitted = submitted
    }

    @Synchronized fun observe(receipts: List<NativeOutcomeReceipt>): Boolean {
        var changed = false
        for (receipt in receipts.take(32)) {
            if (receipt.deliveryId.size != 32 || receipt.observedAtNanos > Long.MAX_VALUE.toULong()) continue
            val observed = receipt.observedAtNanos.toLong()
            val matches = attempts.filter { entry -> entry.ids.any { it.contentEquals(receipt.deliveryId) } }
            val ambiguous = matches.size != 1 || observed <= uncertainUntil
            for (entry in entries.values.filter { candidate -> matches.any { it === candidate } }) {
            if (entry.received != null || observed < entry.started || observed - entry.started > MAX_NANOS) continue
            entry.received = observed; entry.outcome = receipt.outcome; changed = true
            val result = when (receipt.outcome) {
                NativeOutcomeKind.APPROVED -> "approved"
                NativeOutcomeKind.DENIED -> "denied"
                NativeOutcomeKind.FAILED -> "failed"
                NativeOutcomeKind.CANCELLED -> "cancelled"
                NativeOutcomeKind.EXPIRED -> "expired"
                NativeOutcomeKind.EXPIRED_LOCALLY -> "expired_locally"
                NativeOutcomeKind.PC_COMPLETED -> "pc_completed"
            }
            val ready = entry.submitted?.takeIf { it <= observed }
            val actualAuth = entry.authenticated?.takeIf { it <= observed }
            entry.timingAvailable = !ambiguous && ready != null &&
                ((entry.action == NativeRequestAction.APPROVE && receipt.outcome == NativeOutcomeKind.APPROVED && actualAuth != null) ||
                    (entry.action == NativeRequestAction.DENY && receipt.outcome == NativeOutcomeKind.DENIED))
            val auth = actualAuth?.takeIf { entry.timingAvailable }
            val line = "UAC_NATIVE_DECISION_V1 sample=${entry.sample} action=${entry.action.wire} outcome=$result" +
                " timing_eligible=${entry.timingAvailable}" +
                " action_to_receipt_ms=${(observed - entry.started) / 1_000_000}" +
                " action_to_auth_ms=${auth?.let { (it - entry.started) / 1_000_000 } ?: "none"}" +
                " auth_to_receipt_ms=${auth?.let { (observed - it) / 1_000_000 } ?: "none"}" +
                " local_ready_to_receipt_ms=${ready?.let { (observed - it) / 1_000_000 } ?: "none"}"
            try { emit(line) } catch (_: Exception) { /* Diagnostic failure has no action authority. */ }
            }
        }
        return changed
    }

    @Synchronized fun snapshot(now: Long): JSONArray {
        val rows = JSONArray()
        for (entry in entries.values) {
            if (now < entry.started || now - entry.started > MAX_NANOS) continue
            val phase = phase(entry)
            val end = entry.received ?: entry.localStopped ?: now
            val auth = entry.authenticated?.takeIf { it <= end }
            rows.put(JSONObject().put("id", entry.locator).put("action", entry.action.wire).put("phase", phase)
                .put("elapsedMillis", ((end - entry.started) / 1_000_000).coerceIn(0, 300_000))
                .put("timingAvailable", entry.timingAvailable)
                .put("authenticationMillis", auth?.let { (it - entry.started) / 1_000_000 } ?: JSONObject.NULL)
                .put("afterAuthenticationMillis", auth?.takeIf { entry.received != null && entry.timingAvailable }?.let { (end - it) / 1_000_000 } ?: JSONObject.NULL))
        }
        return rows
    }

    @Synchronized fun clear() { entries.clear(); attempts.clear(); uncertainUntil = 0 }
    private fun current(locator: String, observation: NativeDecisionObservation): Entry? =
        entries[locator]?.takeIf { it.observation === observation }
    @Synchronized fun timingAvailable(locator: String): Boolean = entries[locator]?.timingAvailable == true
    /** Same body-free state used by the snapshot; not an action check. */
    @Synchronized fun feedbackPhase(locator: String): String? = entries[locator]?.let(::phase)
    private fun phase(entry: Entry): String = when (entry.outcome) {
        null -> entry.phase
        NativeOutcomeKind.APPROVED -> "approved"
        NativeOutcomeKind.DENIED -> "denied"
        NativeOutcomeKind.FAILED -> "failed"
        NativeOutcomeKind.CANCELLED -> "cancelled"
        NativeOutcomeKind.EXPIRED, NativeOutcomeKind.EXPIRED_LOCALLY -> "expired"
        NativeOutcomeKind.PC_COMPLETED -> "pc_completed"
    }
    override fun toString(): String = "NativeDecisionMeasurements([redacted], display_only)"
    private companion object { const val MAX_NANOS = 300_000_000_000L }
}
