// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.background

import android.Manifest
import android.app.Application
import android.app.KeyguardManager
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Looper
import android.os.SystemClock
import dev.dkk115.uacremote.MainActivity
import dev.dkk115.uacremote.R
import dev.dkk115.uacremote.nativecore.*
import org.json.JSONArray
import org.json.JSONObject
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicBoolean

internal enum class NativeRequestAction(val wire: String) { APPROVE("approve"), DENY("deny"), DETAILS("details") }
internal enum class NativeRequestPhase(val wire: String) {
    PENDING("pending"), AUTHENTICATING("authenticating"), WAITING("waiting"), SENDING("sending"),
    AWAITING_OUTCOME("awaiting_outcome"), UNAVAILABLE("unavailable"),
}
internal enum class NativeRequestActionResult(val wire: String) { QUEUED("queued"), BUSY("busy"), UNAVAILABLE("unavailable"), STALE("stale") }
internal class NativeRequestPayload(val json: String, val generation: Long, val timeEpoch: ULong, val validUntil: ULong) {
    override fun toString(): String = "NativeRequestPayload([redacted])"
}
internal class NativeRequestReview(val locator: String?, val revision: String)
internal class NativeNotificationRoute(val key: String, val locator: String, val action: NativeRequestAction)

/** Locator/formatting rules only: no request, signing or enrollment authority. */
internal object NativeRequestRules {
    const val MAX_REQUESTS = 32
    const val MAX_HANDLES = 64
    const val MAX_LIST_JSON = 512 * 1024
    const val MAX_DETAILS_JSON = 2 * 1024 * 1024
    const val INTENT_ACTION = "dev.dkk115.uacremote.REQUEST_ACTION"
    fun locator(value: String): Boolean = value.length == 32 && value.all { it in '0'..'9' || it in 'a'..'f' }
    fun action(value: String): NativeRequestAction? = NativeRequestAction.values().singleOrNull { it.wire == value }
    fun fullKey(value: String): Boolean = value.length == 194 && value[64] == ':' && value[129] == ':' &&
        value.withIndex().all { (index, item) -> index == 64 || index == 129 || item in '0'..'9' || item in 'a'..'f' }
    fun route(intent: Intent): NativeNotificationRoute? {
        if (intent.action != INTENT_ACTION) return null
        val uri = intent.data ?: return null
        if (uri.toString().length > 512 || uri.scheme != "uac-request" || uri.authority != "selection" || uri.query != null || uri.fragment != null) return null
        val pieces = uri.pathSegments
        if (pieces.size != 3) return null
        return routeParts(pieces[0], pieces[1], pieces[2])
    }
    fun routeParts(key: String, locator: String, action: String): NativeNotificationRoute? {
        if (!fullKey(key) || !NativeRequestRules.locator(locator)) return null
        val kind = if (action == "open") NativeRequestAction.DETAILS else NativeRequestRules.action(action) ?: return null
        return NativeNotificationRoute("request:$key", locator, kind)
    }
    fun mayRouteActivity(restored: Boolean, ownerReady: Boolean, action: NativeRequestAction): Boolean =
        !restored && ownerReady && action != NativeRequestAction.DENY
    fun notificationTag(key: String, locator: String): String {
        require(key.startsWith("request:") && fullKey(key.removePrefix("request:")) && NativeRequestRules.locator(locator))
        return "$key:$locator"
    }
    fun mayRemoveEntry(original: Any, current: Any?): Boolean = original === current
    /** Display cache only; every real action has a separate fresh Rust check. */
    fun displayCurrent(stopped: Boolean, failed: Boolean, temporalInvalid: Boolean, expected: Long, current: Long,
                       expectedEpoch: ULong, currentEpoch: ULong, until: ULong, now: ULong): Boolean =
        !stopped && !failed && !temporalInvalid && expected == current && expectedEpoch == currentEpoch && now < until
    fun remainingSeconds(deadline: ULong, now: ULong): Long {
        if (deadline <= now) return 0
        val difference = deadline - now
        if (difference > 300_000_000_000uL) throw IllegalArgumentException("Invalid request lifetime")
        return ((difference + 999_999_999uL) / 1_000_000_000uL).toLong()
    }
    fun refreshMillis(until: ULong, now: ULong): Long = if (until <= now) 0 else ((until - now) / 1_000_000uL).coerceAtMost(60_000uL).toLong()
}

/** Duplicate intent prevention only; owning live-handle checks remain mandatory. */
internal class NativeRequestActionClaims {
    private val claimed = HashSet<NativeRequestAction>()
    @Synchronized fun claim(action: NativeRequestAction): Boolean = action == NativeRequestAction.DETAILS || claimed.add(action)
}

internal class NativeRequestEntry(val key: String, val locator: String, val selection: NativeRequestSelection, val handle: NativePendingRequest) {
    val lock = Any()
    // Serializes ONLY this generation's OS post/cancel. Never acquired while
    // holding the registry/handle lock, or used to release a body borrow.
    val notificationLock = Any()
    val notificationTag = NativeRequestRules.notificationTag(key, locator)
    @Volatile var active = true
    var readers = 0
    @Volatile var closed = false
    @Volatile var closeFailed = false
    var postedFresh = false
    @Volatile var phase = NativeRequestPhase.PENDING
    @Volatile var displayUntil = 0uL
    var notificationCleared = false
    var notificationFailed = false
    var intents: RequestNotificationActions? = null
    val allocatedIntents = ArrayList<PendingIntent>(4)
    var cancelledIntents = 0
    val notificationClaims = NativeRequestActionClaims()
    @Volatile var delivery: NativeApprovalSubmission? = null
    override fun toString(): String = "NativeRequestEntry([redacted])"
}

/** A short native borrow; retirement waits for it without blocking a callback. */
internal class NativeRequestClaim internal constructor(internal val entry: NativeRequestEntry, private val released: (NativeRequestEntry) -> Unit) : AutoCloseable {
    private val closed = AtomicBoolean(false)
    val handle: NativePendingRequest get() = entry.handle
    val selection: NativeRequestSelection get() = entry.selection
    val locator: String get() = entry.locator
    fun isClosed(): Boolean = closed.get()
    override fun close() { if (closed.compareAndSet(false, true)) released(entry) }
    override fun toString(): String = "NativeRequestClaim([redacted], not_authority)"
}

/** One app-owned bounded projection cache. Bodies/authority remain in Rust. */
internal class NativeRequestRegistry(
    private val application: Application,
    private val clock: NativePresentationClockSource,
    private val changed: () -> Unit,
    private val cleanupProgress: () -> Unit,
) {
    private val lock = Any()
    private val entries = LinkedHashMap<String, NativeRequestEntry>()
    private val retired = ArrayList<NativeRequestEntry>()
    private val temporary = DenialCloseCursor()
    private val deferredClose = ArrayList<AutoCloseable>()
    private val renderer = RequestNotificationRenderer(application)
    private val random = SecureRandom()
    private var generation = 1L
    private var failed = false
    private var stopping = false
    private var temporalInvalid = false
    private var clearRequested = false
    private var clearFailed = false
    private var allNotificationsCleared = false
    private var lastCatalog: String? = null
    private var catalogReady = false
    private var reviewLocator: String? = null
    private var reviewRevision = 0uL

    fun publish(request: NativePendingRequest, intent: NativeRequestPresentation, alert: NativeRequestAlert): NativeRequestSinkOutcome {
        var retained = false
        var entry: NativeRequestEntry? = null
        var borrowed: NativeRequestEntry? = null
        var replaced: NativeRequestEntry? = null
        try {
            val observed = clock.observe()
            val preview = request.preview(observed)
            val selection = NativeRequestIdentity.copy(preview.selection) ?: throw BridgeException.NativeUnavailable()
            val key = NativeRequestIdentity.notificationTag(selection)
            synchronized(lock) {
                if (failed || stopping || entries.size + retired.size >= NativeRequestRules.MAX_HANDLES) throw BridgeException.NativeUnavailable()
                val current = entries[key]
                if (current != null && current.handle.sameHandle(request)) {
                    entry = current
                    retained = current.handle === request
                } else {
                    if (current == null && entries.size >= NativeRequestRules.MAX_REQUESTS) throw BridgeException.NativeUnavailable()
                    val next = NativeRequestEntry(key, newLocator(), selection, request)
                    next.displayUntil = preview.validUntilNanos
                    if (current != null) {
                        synchronized(current.lock) {
                            next.phase = current.phase; next.delivery = current.delivery; current.delivery = null
                            next.postedFresh = current.postedFresh
                        }
                        retireLocked(current)
                        replaced = current
                    }
                    entries[key] = next; entry = next; retained = true
                    temporalInvalid = false; bump()
                }
                val selected = entry ?: throw BridgeException.NativeUnavailable()
                synchronized(selected.lock) {
                    if (!selected.active || selected.closed || selected.closeFailed) throw BridgeException.NativeUnavailable()
                    selected.readers += 1; borrowed = selected
                }
            }
            val owned = entry ?: throw BridgeException.NativeUnavailable()
            closeRetired(false)
            // A reader may still retain the old body, but that does not delay
            // retiring its OS notification before the new generation posts.
            if (replaced?.let { synchronized(it.notificationLock) { !it.notificationCleared } } == true) throw BridgeException.NativeUnavailable()
            changed() // Retained list state also changes when OS posting is blocked.
            val mode = when (alert) {
                NativeRequestAlert.SOUND -> RequestNotificationMode.SOUND
                NativeRequestAlert.VIBRATION_ONLY -> RequestNotificationMode.VIBRATION_ONLY
                NativeRequestAlert.SILENT -> RequestNotificationMode.SILENT
            }
            val lockConfigured = application.getSystemService(KeyguardManager::class.java)?.isDeviceSecure
                ?: throw BridgeException.NativeUnavailable()
            if (!lockConfigured) return NativeRequestSinkOutcome.RetainedNotPosted(NativeRequestNotPosted.SECURE_LOCK_MISSING)
            if (Build.VERSION.SDK_INT >= 33 && application.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
                return NativeRequestSinkOutcome.RetainedNotPosted(NativeRequestNotPosted.PERMISSION_MISSING)
            }
            val manager = application.getSystemService(NotificationManager::class.java) ?: throw BridgeException.NativeUnavailable()
            if (!manager.areNotificationsEnabled()) return NativeRequestSinkOutcome.RetainedNotPosted(NativeRequestNotPosted.NOTIFICATIONS_DISABLED)
            renderer.ensureChannels()
            if (!renderer.channelEnabled(mode)) return NativeRequestSinkOutcome.RetainedNotPosted(NativeRequestNotPosted.NOTIFICATIONS_DISABLED)
            val current = checkedPreview(owned)
            val quiet = synchronized(owned.lock) {
                val value = RequestNotificationPolicy.quiet(intent == NativeRequestPresentation.FRESH, owned.postedFresh)
                owned.postedFresh = true // Before notify: uncertain attempts cannot re-alert.
                value
            }
            val intents = synchronized(owned.lock) { owned.intents ?: actions(owned).also { owned.intents = it } }
            val now = SystemClock.elapsedRealtimeNanos()
            if (now < 0 || current.deadlineNanos <= now.toULong() || current.validUntilNanos <= now.toULong()) throw BridgeException.RequestUnavailable()
            val remaining = ((current.deadlineNanos - now.toULong()) / 1_000_000uL).toLong()
            if (remaining <= 0) throw BridgeException.RequestUnavailable()
            val notification = renderer.build(RequestNotificationContent(current.program, current.path), mode, quiet, remaining, intents)
            synchronized(owned.notificationLock) {
                checkedPreview(owned)
                if (owned.notificationFailed) throw BridgeException.NativeUnavailable()
                owned.notificationCleared = false
                synchronized(lock) { allNotificationsCleared = false }
                renderer.post(owned.notificationTag, notification) // OS attempt only.
                try { checkedPreview(owned) }
                catch (_: Exception) {
                    try { renderer.withdraw(owned.notificationTag); owned.notificationCleared = true }
                    catch (_: Exception) { owned.notificationFailed = true; throw BridgeException.NativeUnavailable() }
                    throw BridgeException.RequestUnavailable()
                }
            }
            changed()
            return NativeRequestSinkOutcome.RetainedAndPostRequested
        } catch (_: BridgeException.PresentationRefreshRequired) {
            entry?.let { discardEntry(it) }
            return NativeRequestSinkOutcome.DiscardedStale
        } catch (_: BridgeException.RequestUnavailable) {
            entry?.let { discardEntry(it) }
            return NativeRequestSinkOutcome.DiscardedStale
        } catch (_: Exception) {
            synchronized(lock) { failed = true }
            throw BridgeException.NativeUnavailable()
        } finally {
            borrowed?.let { releaseBorrow(it) }
            if (!retained) closeTemporary(request)
        }
    }

    fun acquire(locator: String, action: NativeRequestAction? = null, notification: Boolean = false): NativeRequestClaim? {
        if (!NativeRequestRules.locator(locator)) return null
        val entry = synchronized(lock) {
            if (failed || stopping || temporalInvalid || !catalogReady) return null
            entries.values.singleOrNull { it.locator == locator } ?: return null
        }
        synchronized(entry.lock) {
            if (!entry.active || entry.closed || entry.closeFailed) return null
            if (notification && action != null && !entry.notificationClaims.claim(action)) return null
            entry.readers += 1
        }
        return NativeRequestClaim(entry, ::releaseBorrow)
    }
    fun current(claim: NativeRequestClaim): Boolean = !claim.isClosed() && try { checkedPreview(claim.entry); true } catch (_: Exception) { false }
    fun acquireNotification(route: NativeNotificationRoute): NativeRequestClaim? {
        val currentKey = synchronized(lock) { entries.values.singleOrNull { it.locator == route.locator }?.key }
        return if (currentKey == route.key) acquire(route.locator, route.action, true) else null
    }
    fun preview(claim: NativeRequestClaim): NativeRequestPreview {
        if (claim.isClosed()) throw BridgeException.RequestUnavailable()
        return checkedPreview(claim.entry)
    }
    fun phase(locator: String, value: NativeRequestPhase) {
        val modified = synchronized(lock) {
            val entry = entries.values.singleOrNull { it.locator == locator } ?: return@synchronized false
            synchronized(entry.lock) { if (entry.phase == value) false else { entry.phase = value; bump(); true } }
        }
        if (modified) changed()
    }
    fun keepDelivery(locator: String, value: NativeApprovalSubmission): Boolean {
        val entry = synchronized(lock) { entries.values.singleOrNull { it.locator == locator && it.active } }
        if (entry == null) { closeTemporary(value); return false }
        val accepted = synchronized(entry.lock) {
            if (!entry.active || entry.closed || entry.delivery != null) false else { entry.delivery = value; true }
        }
        if (!accepted) closeTemporary(value)
        return accepted
    }
    fun deliveries(): List<Pair<String, NativeApprovalSubmission>> = synchronized(lock) {
        entries.values.mapNotNull { entry -> synchronized(entry.lock) { entry.delivery?.let { entry.locator to it } } }
    }
    fun nextWake(): ULong? {
        val all = synchronized(lock) { if (stopping || failed || temporalInvalid) return null; entries.values.toList() }
        return all.map { entry -> try { checkedPreview(entry).validUntilNanos } catch (_: Exception) { entry.displayUntil } }.minOrNull()
    }
    fun openReview(claim: NativeRequestClaim) {
        if (!current(claim)) throw BridgeException.RequestUnavailable()
        synchronized(lock) {
            if (reviewRevision == ULong.MAX_VALUE) throw BridgeException.NativeUnavailable()
            reviewLocator = claim.locator; reviewRevision += 1u
        }
        changed()
    }
    fun review(): NativeRequestReview {
        val locator = synchronized(lock) { reviewLocator }
        val claim = locator?.let { acquire(it) }
        val live = try { claim != null && current(claim) } finally { claim?.close() }
        return synchronized(lock) {
            if (!live) reviewLocator = null
            NativeRequestReview(reviewLocator, reviewRevision.toString())
        }
    }

    fun snapshot(catalog: NativeRequestCatalogStatus, canApprove: (NativeRequestSelection) -> Boolean, canDeny: (NativeRequestSelection) -> Boolean): NativeRequestPayload {
        val originalGeneration = synchronized(lock) { generation }
        val observed = clock.observe()
        val rows = JSONArray()
        var until = observed.elapsedAfterNanos + 1_000_000_000uL
        val all = synchronized(lock) { if (failed || stopping) throw BridgeException.NativeUnavailable(); entries.values.toList() }
        var omitted = false
        for (entry in all) {
            val claim = acquire(entry.locator)
            if (claim == null) { omitted = true; continue }
            try {
                val value = claim.handle.preview(observed)
                if (!current(claim)) { omitted = true; continue }
                until = minOf(until, value.validUntilNanos)
                val state = synchronized(entry.lock) { entry.phase }
                rows.put(JSONObject().put("id", entry.locator).put("computerName", application.getString(R.string.request_computer_context))
                    .put("programName", value.program).put("executablePath", value.path).put("programElided", value.programElided).put("pathElided", value.pathElided)
                    .put("hasDetails", value.hasDetails).put("remainingSeconds", NativeRequestRules.remainingSeconds(value.deadlineNanos, observed.elapsedAfterNanos))
                    .put("refreshAfterMillis", NativeRequestRules.refreshMillis(value.validUntilNanos, observed.elapsedAfterNanos)).put("state", state.wire)
                    .put("canApprove", state == NativeRequestPhase.PENDING && canApprove(entry.selection)).put("canDeny", state != NativeRequestPhase.UNAVAILABLE && canDeny(entry.selection)))
            } catch (_: BridgeException.RequestUnavailable) { omitted = true }
            finally { claim.close() }
        }
        val status = when (catalog.state) {
            NativeRequestCatalogState.UNAVAILABLE -> "unavailable"
            NativeRequestCatalogState.RECONCILING -> "reconciling"
            NativeRequestCatalogState.READY -> if (omitted || rows.length() != catalog.requestCount.toInt() || synchronized(lock) { temporalInvalid }) "reconciling" else "ready"
        }
        if (catalog.configuredPeers > 32u || catalog.connectedPeers > catalog.configuredPeers || rows.length() > NativeRequestRules.MAX_REQUESTS ||
            (catalog.configuredPeers == 0.toUByte() && rows.length() != 0)) throw BridgeException.NativeUnavailable()
        val root = JSONObject().put("version", 1).put("status", status).put("revision", catalog.revision.toString())
            .put("peerCount", catalog.configuredPeers.toInt()).put("connectedPeerCount", catalog.connectedPeers.toInt()).put("requests", rows)
        return payload(root, NativeRequestRules.MAX_LIST_JSON, observed, until, originalGeneration)
    }
    fun details(claim: NativeRequestClaim): NativeRequestPayload {
        val originalGeneration = synchronized(lock) { generation }
        val observed = clock.observe()
        val preview = claim.handle.preview(observed)
        val value = claim.handle.details(observed)
        // Rust's per-field96KiB UTF-8 bound limits construction before JSON
        // escaping (worst case6x); never concatenate an unbounded bridge value.
        if (listOf(value.program, value.path, value.details).any { it.length > 96 * 1024 || it.toByteArray(Charsets.UTF_8).size > 96 * 1024 }) throw BridgeException.NativeUnavailable()
        if (!current(claim)) throw BridgeException.RequestUnavailable()
        val root = JSONObject().put("version", 1).put("id", claim.locator).put("programName", value.program).put("executablePath", value.path).put("details", value.details)
            .put("remainingSeconds", NativeRequestRules.remainingSeconds(preview.deadlineNanos, observed.elapsedAfterNanos))
            .put("refreshAfterMillis", NativeRequestRules.refreshMillis(preview.validUntilNanos, observed.elapsedAfterNanos))
        return payload(root, NativeRequestRules.MAX_DETAILS_JSON, observed, preview.validUntilNanos, originalGeneration)
    }
    fun validReply(value: NativeRequestPayload): Boolean = try {
        val observed = clock.observe()
        synchronized(lock) { NativeRequestRules.displayCurrent(stopping, failed, temporalInvalid, value.generation, generation,
            value.timeEpoch, observed.timeEpoch, value.validUntil, observed.elapsedAfterNanos) }
    } catch (_: Exception) { false }

    fun withdraw(selection: NativeRequestSelection) {
        val key = NativeRequestIdentity.notificationTag(selection)
        synchronized(lock) { entries.remove(key)?.let { retireLocked(it); bump() } }
        closeRetired(false)
        changed()
        if (notificationCleanupFailed(key)) throw BridgeException.NativeUnavailable()
    }
    private fun discardEntry(entry: NativeRequestEntry) {
        synchronized(lock) {
            // A stale publisher may remove only its original generation, never
            // a replacement stored under the same original request selection.
            if (NativeRequestRules.mayRemoveEntry(entry, entries[entry.key])) {
                entries.remove(entry.key); retireLocked(entry); bump()
            }
        }
        closeRetired(false); changed()
        if (synchronized(entry.notificationLock) { entry.notificationFailed }) throw BridgeException.NativeUnavailable()
    }
    private fun notificationCleanupFailed(key: String): Boolean {
        val selected = synchronized(lock) { retired.filter { it.key == key } }
        return selected.any { synchronized(it.notificationLock) { it.notificationFailed } }
    }
    fun invalidateTime() { synchronized(lock) { temporalInvalid = true; bump() }; changed() }
    fun catalogMaintained(catalog: NativeRequestCatalogStatus) {
        val identity = "${catalog.state}:${catalog.revision}:${catalog.requestCount}:${catalog.configuredPeers}:${catalog.attachedPeers}:${catalog.connectedPeers}"
        val modified = synchronized(lock) {
            val result = (temporalInvalid && catalog.state == NativeRequestCatalogState.READY) || lastCatalog != identity
            catalogReady = catalog.state == NativeRequestCatalogState.READY
            if (catalogReady) temporalInvalid = false
            lastCatalog = identity
            if (result) bump()
            result
        }
        if (modified) changed()
    }
    fun clear() {
        synchronized(lock) { for (entry in entries.values.toList()) retireLocked(entry); entries.clear(); if (!allNotificationsCleared) clearRequested = true; bump() }
        if (!continueCleanup()) throw BridgeException.NativeUnavailable()
        changed()
    }
    fun stop() {
        synchronized(lock) {
            stopping = true
            for (entry in entries.values.toList()) retireLocked(entry)
            entries.clear(); if (!allNotificationsCleared) clearRequested = true; bump()
        }
        cleanupProgress(); changed()
    }
    fun continueCleanup(): Boolean = cleanup(false)
    fun retryCleanup(): Boolean = cleanup(true)
    private fun cleanup(explicit: Boolean): Boolean {
        if (Looper.myLooper() == Looper.getMainLooper()) { cleanupProgress(); return false }
        val clear = synchronized(lock) { clearRequested && (!clearFailed || explicit) }
        if (clear) try {
            renderer.clearOwned()
            synchronized(lock) { clearRequested = false; clearFailed = false; allNotificationsCleared = true }
        } catch (_: Exception) { synchronized(lock) { clearFailed = true } }
        closeRetired(explicit)
        val deferred = synchronized(lock) { deferredClose.toList() }
        for (value in deferred) {
            try { temporary.closeOrRetain(value) }
            catch (_: Exception) { synchronized(lock) { failed = true } }
            finally { synchronized(lock) { deferredClose.remove(value) } }
        }
        val arguments = if (explicit) temporary.retryOnce() else temporary.complete()
        val selected = synchronized(lock) { retired.toList() }
        return arguments && synchronized(lock) { !clearRequested && !clearFailed && retired.none { it.closeFailed } } &&
            selected.none { synchronized(it.notificationLock) { it.notificationFailed } }
    }
    fun cleanupComplete(): Boolean = synchronized(lock) { entries.isEmpty() && retired.isEmpty() && deferredClose.isEmpty() && !clearRequested && !clearFailed && temporary.complete() }

    private fun checkedPreview(entry: NativeRequestEntry): NativeRequestPreview {
        val observed = clock.observe() // Its invalidation callback never runs under a registry/entry lock.
        synchronized(lock) { if (failed || stopping || temporalInvalid || entries[entry.key] !== entry) throw BridgeException.RequestUnavailable() }
        synchronized(entry.lock) {
            if (!entry.active || entry.closed || entry.closeFailed || entry.handle.isRevoked()) throw BridgeException.RequestUnavailable()
            val value = entry.handle.preview(observed)
            if (!NativeRequestIdentity.same(value.selection, entry.selection) || value.program.length > 512 || value.path.length > 1024) throw BridgeException.NativeUnavailable()
            entry.displayUntil = value.validUntilNanos
            return value
        }
    }
    private fun payload(value: JSONObject, limit: Int, observed: NativePresentationClock, until: ULong, expectedGeneration: Long): NativeRequestPayload {
        val json = value.toString()
        if (json.length > limit || json.toByteArray(Charsets.UTF_8).size > limit) throw BridgeException.NativeUnavailable()
        if (synchronized(lock) { generation != expectedGeneration }) throw BridgeException.RequestUnavailable()
        return NativeRequestPayload(json, expectedGeneration, observed.timeEpoch, until)
    }
    private fun releaseBorrow(entry: NativeRequestEntry) {
        synchronized(entry.lock) { check(entry.readers > 0); entry.readers -= 1 }
        if (!entry.active) cleanupProgress()
    }
    private fun retireLocked(entry: NativeRequestEntry) {
        synchronized(entry.lock) {
            entry.active = false
        }
        if (reviewLocator == entry.locator) reviewLocator = null
        if (!retired.contains(entry)) retired.add(entry)
    }
    private fun closeRetired(explicit: Boolean) {
        if (Looper.myLooper() == Looper.getMainLooper()) { cleanupProgress(); return }
        val copy = synchronized(lock) { retired.toList() }
        for (entry in copy) {
            // Notification retirement is independent of body readers. The
            // unique tag and this lock prevent late-old post/compensation from
            // touching a newer generation's notification.
            val withdrawn = synchronized(entry.notificationLock) {
                if (entry.notificationFailed && !explicit) false
                else try {
                    if (!entry.notificationCleared) renderer.withdraw(entry.notificationTag)
                    entry.notificationCleared = true; entry.notificationFailed = false; true
                } catch (_: Exception) { entry.notificationFailed = true; false }
            }
            if (!withdrawn) continue
            val done = synchronized(entry.lock) {
                if (entry.readers != 0 || (entry.closeFailed && !explicit)) false
                else try {
                    while (entry.cancelledIntents < entry.allocatedIntents.size) {
                        entry.allocatedIntents[entry.cancelledIntents].cancel(); entry.cancelledIntents += 1
                    }
                    entry.intents = null
                    entry.delivery?.let { it.close(); entry.delivery = null }
                    if (!entry.closed) { entry.handle.close(); entry.closed = true }
                    entry.closeFailed = false; true
                } catch (_: Exception) { entry.closeFailed = true; false }
            }
            if (done) synchronized(lock) { retired.remove(entry) }
        }
    }
    private fun closeTemporary(value: AutoCloseable) {
        if (synchronized(lock) { entries.values.any { it.handle === value || it.delivery === value } || retired.any { it.handle === value || it.delivery === value } }) return
        if (Looper.myLooper() == Looper.getMainLooper()) {
            synchronized(lock) {
                if (deferredClose.any { it === value }) return
                // Only the single native approval slot can publish these on
                // main; failure blocks further actions before this cap.
                if (deferredClose.size >= NativeRequestRules.MAX_REQUESTS) throw BridgeException.NativeUnavailable()
                deferredClose.add(value)
            }
            cleanupProgress()
            return
        }
        try { temporary.closeOrRetain(value) } catch (_: Exception) { synchronized(lock) { failed = true }; throw BridgeException.NativeUnavailable() }
    }
    private fun newLocator(): String {
        repeat(4) {
            val value = ByteArray(16).also { random.nextBytes(it) }.joinToString("") { (it.toInt() and 255).toString(16).padStart(2, '0') }
            if (entries.values.none { it.locator == value } && retired.none { it.locator == value }) return value
        }
        throw BridgeException.NativeUnavailable()
    }
    private fun actions(entry: NativeRequestEntry): RequestNotificationActions {
        fun pending(action: NativeRequestAction, content: Boolean = false): PendingIntent {
            val data = Uri.Builder().scheme("uac-request").authority("selection").appendPath(entry.key.removePrefix("request:"))
                .appendPath(entry.locator).appendPath(if (content) "open" else action.wire).build()
            val target = if (action == NativeRequestAction.DENY) ControllerRequestActionReceiver::class.java else MainActivity::class.java
            val intent = Intent(application, target).setAction(NativeRequestRules.INTENT_ACTION).setData(data)
            val flags = PendingIntent.FLAG_IMMUTABLE or if (action == NativeRequestAction.DETAILS || content) PendingIntent.FLAG_UPDATE_CURRENT else PendingIntent.FLAG_ONE_SHOT
            val result = if (action == NativeRequestAction.DENY) PendingIntent.getBroadcast(application, 0, intent, flags)
            else PendingIntent.getActivity(application, 0, intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP), flags)
            entry.allocatedIntents.add(result) // Retain before constructing any later intent.
            return result
        }
        return RequestNotificationActions(pending(NativeRequestAction.DETAILS, true), pending(NativeRequestAction.APPROVE), pending(NativeRequestAction.DENY), pending(NativeRequestAction.DETAILS))
    }
    private fun bump() { if (generation == Long.MAX_VALUE) { failed = true; throw BridgeException.NativeUnavailable() }; generation += 1 }
    override fun toString(): String = "NativeRequestRegistry([redacted], projections_only)"
}
