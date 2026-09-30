// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.background

import android.annotation.TargetApi
import android.content.Context
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import android.os.Build
import android.os.Handler
import android.os.Looper
import java.net.InetAddress
import java.util.concurrent.Executor

/** Main-thread-owned, bounded DNS-SD routing hints. Native pinned TLS still authenticates every dial. */
internal class LanServiceDiscovery(context: Context, private val main: Handler,
    private val onSeen: (String, List<String>, Int) -> Unit,
    private val onLost: (String) -> Unit) {
    private val manager = try { context.getSystemService(NsdManager::class.java) } catch (_: Exception) { null }
    private val executor = Executor { main.post(it) }
    private var wanted = false
    private var closed = false
    private var session: Session? = null
    // API 31-33 cannot cancel a resolve. Retain its slot across stop/start until its terminal callback.
    private var resolving: Entry? = null
    private val queue = ArrayDeque<Entry>()

    fun setWanted(value: Boolean) {
        check(Looper.myLooper() == main.looper)
        wanted = value && !closed
        val current = session
        if (!wanted) current?.stop()
        else if (current == null && manager != null) {
            val next = Session()
            session = next
            try { manager.discoverServices(SERVICE_TYPE, NsdManager.PROTOCOL_DNS_SD, next) }
            catch (_: Exception) { next.stop() }
        }
    }

    fun close() {
        closed = true
        setWanted(false)
    }

    private inner class Entry(val owner: Session, val info: NsdServiceInfo) {
        val instance: String = info.serviceName
        var unregister: (() -> Unit)? = null
        fun current(): Boolean = owner.active() && owner.entries[instance] === this
    }

    private inner class Session : NsdManager.DiscoveryListener {
        val entries = linkedMapOf<String, Entry>()
        private var stopping = false
        private var stopPending = false
        private val retryStop = Runnable { requestStop() }
        fun active(): Boolean = session === this && wanted && !closed && !stopping

        fun stop() {
            if (!stopping) {
                stopping = true
                clearEntries()
            }
            if (!stopPending) requestStop()
        }

        private fun clearEntries() {
            val previous = entries.values.toList()
            entries.clear()
            queue.removeAll { it.owner === this }
            previous.forEach { it.unregister?.invoke() }
        }

        private fun requestStop() {
            if (session !== this || stopPending) return
            main.removeCallbacks(retryStop)
            try {
                manager?.stopServiceDiscovery(this)
                stopPending = true
            } catch (_: IllegalArgumentException) {
                // NsdManager already removed this listener (including failed starts).
                finished(false)
            } catch (_: Exception) {
                // Keep the exact listener until cleanup succeeds; never register a replacement over it.
                main.postDelayed(retryStop, CLEANUP_RETRY_MILLIS)
            }
        }

        private fun finished(restart: Boolean) {
            if (session !== this) return
            stopping = true
            main.removeCallbacks(retryStop)
            clearEntries()
            session = null
            if (restart && wanted && !closed) setWanted(true)
        }

        override fun onDiscoveryStarted(serviceType: String) { main.post { if (!active()) stop() } }
        override fun onStartDiscoveryFailed(serviceType: String, errorCode: Int) {
            // Android removes the listener before both failure callbacks; no duplicate stop/register.
            main.post { finished(false) }
        }
        override fun onStopDiscoveryFailed(serviceType: String, errorCode: Int) {
            main.post { finished(true) }
        }
        override fun onDiscoveryStopped(serviceType: String) { main.post { finished(true) } }
        override fun onServiceFound(serviceInfo: NsdServiceInfo) {
            main.post {
                val name = serviceInfo.serviceName ?: return@post
                if (!active() || !LanDiscoveryPolicy.matches(name) || entries.containsKey(name) ||
                    entries.size >= MAX_SERVICES) return@post
                val entry = Entry(this, serviceInfo)
                entries[name] = entry
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) watch(entry)
                else { queue.addLast(entry); resolveNext() }
            }
        }
        override fun onServiceLost(serviceInfo: NsdServiceInfo) {
            main.post {
                if (!active()) return@post
                entries[serviceInfo.serviceName]?.let { lost(it) }
            }
        }
    }

    private fun lost(entry: Entry) {
        if (!entry.current()) return
        entry.owner.entries.remove(entry.instance)
        queue.remove(entry)
        entry.unregister?.invoke()
        onLost(entry.instance)
    }

    private fun report(entry: Entry, addresses: List<InetAddress>, port: Int) {
        if (!entry.current() || port !in 1..65535) return
        val values = addresses.mapNotNull { it.hostAddress?.substringBefore('%') }
            .filter { it.isNotEmpty() }.distinct().take(MAX_ADDRESSES)
        if (values.isNotEmpty()) onSeen(entry.instance, values, port)
    }

    @TargetApi(34)
    private fun watch(entry: Entry) {
        val callback = object : NsdManager.ServiceInfoCallback {
            private var unregistering = false
            private var registered = true
            private val retry = Runnable { unregister() }
            fun unregister() {
                if (!registered || unregistering) return
                main.removeCallbacks(retry)
                try {
                    manager?.unregisterServiceInfoCallback(this)
                    unregistering = true
                } catch (_: IllegalArgumentException) { registered = false }
                catch (_: Exception) { main.postDelayed(retry, CLEANUP_RETRY_MILLIS) }
            }
            override fun onServiceInfoCallbackRegistrationFailed(errorCode: Int) {
                main.post {
                    registered = false
                    main.removeCallbacks(retry)
                    if (entry.current()) entry.owner.entries.remove(entry.instance)
                }
            }
            override fun onServiceUpdated(serviceInfo: NsdServiceInfo) {
                main.post { report(entry, serviceInfo.hostAddresses, serviceInfo.port) }
            }
            override fun onServiceLost() { main.post { lost(entry) } }
            override fun onServiceInfoCallbackUnregistered() {
                main.post { registered = false; main.removeCallbacks(retry) }
            }
        }
        entry.unregister = callback::unregister
        try { manager?.registerServiceInfoCallback(entry.info, executor, callback) }
        catch (_: Exception) {
            entry.owner.entries.remove(entry.instance)
            callback.unregister()
        }
    }

    @Suppress("DEPRECATION") // API 31-33 have only the single-address resolve API.
    private fun resolveNext() {
        if (resolving != null) return
        while (queue.isNotEmpty()) {
            val entry = queue.removeFirst()
            if (!entry.current()) continue
            resolving = entry
            val callback = object : NsdManager.ResolveListener {
                override fun onResolveFailed(serviceInfo: NsdServiceInfo, errorCode: Int) {
                    main.post {
                        if (resolving !== entry) return@post
                        resolving = null
                        if (entry.current()) entry.owner.entries.remove(entry.instance)
                        resolveNext()
                    }
                }
                override fun onServiceResolved(serviceInfo: NsdServiceInfo) {
                    main.post {
                        if (resolving !== entry) return@post
                        resolving = null
                        report(entry, listOfNotNull(serviceInfo.host), serviceInfo.port)
                        resolveNext()
                    }
                }
            }
            try { manager?.resolveService(entry.info, callback) }
            catch (_: Exception) {
                resolving = null
                if (entry.current()) entry.owner.entries.remove(entry.instance)
                continue
            }
            return
        }
    }

    companion object {
        // Must match service_protocol::LAN_SERVICE_TYPE; DNS-SD is an unsigned routing hint only.
        private const val SERVICE_TYPE = "_uacremote._tcp"
        private const val MAX_SERVICES = 32
        private const val MAX_ADDRESSES = 8
        private const val CLEANUP_RETRY_MILLIS = 15_000L
    }
}
