// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.pairing

import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.hardware.usb.UsbAccessory
import android.hardware.usb.UsbManager
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.system.Os
import android.system.OsConstants
import android.system.StructPollfd
import android.util.Base64
import dev.dkk115.uacremote.MainActivity
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean

/** One bounded, read-only AOA receive; no URL, filename, key or decision channel. */
internal class PairingUsbSession(
    private val activity: MainActivity,
    private val currentHost: () -> Boolean,
    private val received: (String?) -> Unit,
    private val released: () -> Unit,
) {
    private val main = Handler(Looper.getMainLooper())
    private val manager = activity.getSystemService(UsbManager::class.java)
    private val stopped = AtomicBoolean(false)
    private val started = SystemClock.elapsedRealtime()
    private val action = "${activity.packageName}.USB_BOOTSTRAP.${UUID.randomUUID()}"
    private var accessory: UsbAccessory? = null
    private var registered = false
    private var pending: PendingIntent? = null
    private var permissionReturned = false
    private var workerStarted = false
    private var finished = false
    var permissionPending: Boolean = false
        private set
    private val timeout = Runnable { fail() }
    private val discover = Runnable { discoverAccessory() }
    private val receiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            if (intent.action != action || !permissionPending || stopped.get()) return
            // A broadcast is only a wake-up. Never trust its permission flag or
            // nominated accessory; query the OS for the retained exact object.
            permissionReturned = true
            if (currentHost()) resume()
        }
    }

    fun start() {
        check(Looper.myLooper() == Looper.getMainLooper())
        if (!currentHost() || manager == null || !main.postDelayed(timeout, 30_000)) { fail(); return }
        discoverAccessory()
    }

    private fun discoverAccessory() {
        if (stopped.get() || !currentHost() || manager == null) { close(); return }
        try {
            val matches = manager.accessoryList.orEmpty().filter {
                it.manufacturer == "UAC Remote" && it.model == "UAC Remote Approval" && it.version == "1"
            }
            if (matches.isEmpty()) { if (!main.postDelayed(discover, 250)) fail(); return }
            if (matches.size != 1) { fail(); return }
            val selected = matches.single()
            accessory = selected
            if (manager.hasPermission(selected)) { read(); return }
            if (Build.VERSION.SDK_INT >= 33) activity.registerReceiver(receiver, IntentFilter(action), Context.RECEIVER_NOT_EXPORTED)
            else registerLegacy()
            registered = true
            val intent = Intent(action).setPackage(activity.packageName)
            pending = PendingIntent.getBroadcast(activity, 0, intent, PendingIntent.FLAG_ONE_SHOT or PendingIntent.FLAG_IMMUTABLE)
            permissionPending = true
            manager.requestPermission(selected, pending)
        } catch (_: Exception) { fail() }
    }

    @Suppress("DEPRECATION")
    private fun registerLegacy() { activity.registerReceiver(receiver, IntentFilter(action)) }

    fun resume() {
        if (stopped.get() || !permissionReturned || !currentHost()) return
        permissionPending = false
        permissionReturned = false
        val selected = accessory
        if (selected == null || manager?.hasPermission(selected) != true) fail() else read()
    }

    private fun read() {
        if (workerStarted || stopped.get() || !currentHost()) return
        val selected = accessory ?: run { fail(); return }
        workerStarted = true
        val worker = Thread({
            var invitation: String? = null
            try {
                manager?.openAccessory(selected)?.use { descriptor ->
                    val poll = StructPollfd().apply { fd = descriptor.fileDescriptor; events = OsConstants.POLLIN.toShort() }
                    // Android accessory reads discard a remainder when a USB
                    // packet exceeds the read buffer. Read a full 16 KiB packet,
                    // then enforce the much smaller application-frame bound.
                    val packet = ByteArray(16_384)
                    val frame = ByteArray(PairingUsbFrame.MAX_FRAME)
                    var count = 0
                    while (!stopped.get() && SystemClock.elapsedRealtime() - started < 30_000) {
                        if (Os.poll(arrayOf(poll), 200) == 0) continue
                        if ((poll.revents.toInt() and OsConstants.POLLIN) == 0) break
                        val read = Os.read(descriptor.fileDescriptor, packet, 0, packet.size)
                        if (read <= 0 || count + read > frame.size) break
                        packet.copyInto(frame, count, 0, read)
                        count += read
                        if (count >= PairingUsbFrame.HEADER) {
                            val length = PairingUsbFrame.length(frame, count) ?: break
                            if (count > length) break
                            if (count == length) {
                                val body = PairingUsbFrame.body(frame, count) ?: break
                                invitation = "uac-remote:v1:" + Base64.encodeToString(body, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
                                body.fill(0)
                                break
                            }
                        }
                    }
                    frame.fill(0); packet.fill(0)
                }
            } catch (_: Exception) { /* Fixed failure UI; never log accessory data. */ }
            finally {
                val result = invitation
                main.post {
                    if (!stopped.get() && currentHost()) received(result)
                    stopped.set(true)
                    finish()
                }
            }
        }, "uac-usb-bootstrap").apply { isDaemon = true }
        try { worker.start() }
        catch (_: Exception) { workerStarted = false; fail() }
    }

    private fun fail() {
        if (!stopped.get() && currentHost()) received(null)
        close()
    }

    fun close() {
        stopped.set(true)
        permissionPending = false
        main.removeCallbacks(timeout)
        main.removeCallbacks(discover)
        pending?.cancel(); pending = null
        if (registered) { try { activity.unregisterReceiver(receiver) } catch (_: Exception) { }; registered = false }
        // Poll timeout releases the original descriptor on its owning thread.
        // The dialog slot remains occupied until that actual release is observed.
        if (!workerStarted) finish()
    }

    private fun finish() {
        if (finished) return
        finished = true
        main.removeCallbacks(timeout)
        main.removeCallbacks(discover)
        pending?.cancel(); pending = null
        if (registered) { try { activity.unregisterReceiver(receiver) } catch (_: Exception) { }; registered = false }
        released()
    }
}
