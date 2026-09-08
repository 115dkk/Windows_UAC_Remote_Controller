// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.background

import android.app.Application
import android.os.Looper
import android.os.UserManager
import dev.dkk115.uacremote.nativecore.BridgeException
import java.io.File
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.NoSuchFileException
import java.nio.file.OpenOption
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.BasicFileAttributes
import java.security.KeyStore

/** Read-only bootstrap observations. Rust owns every migration/bootstrap decision and write. */
internal class LegacyPolicyObservation(private val application: Application) {
    fun legacyPolicyDocument(): String? = try {
        requireAvailable()
        // Verified in installed Tauri 2.11.5: app_data_dir -> getDataDir ->
        // Activity.dataDir, NOT filesDir. Application resolves the same app user.
        val nativeBase: File = application.dataDir
        requireDirectory(nativeBase)
        val base = nativeBase.canonicalFile
        requireDirectory(base)
        val staging = File(base, "notification-policy.staging")
        val lock = File(base, "notification-policy.lock")
        val document = File(base, "notification-policy.json")
        ensureNoStaging(staging)
        attributes(lock)?.let { if (!it.isRegularFile || it.isSymbolicLink || it.size() != 0L) unavailable() }
        val before = attributes(document)
        if (before == null) {
            ensureNoStaging(staging)
            requireDirectory(nativeBase)
            requireDirectory(base)
            if (nativeBase.canonicalFile != base || document.canonicalFile != document) unavailable()
            requireAvailable()
            null
        } else {
            if (!before.isRegularFile || before.isSymbolicLink || before.size() > PolicyOwnerBounds.MAX_POLICY_BYTES) unavailable()
            if (document.canonicalFile != document || document.parentFile != base) unavailable()
            val buffer = ByteBuffer.allocate(PolicyOwnerBounds.MAX_POLICY_BYTES + 1)
            Files.newByteChannel(document.toPath(), setOf<OpenOption>(StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)).use { channel ->
                while (buffer.hasRemaining()) {
                    val count = channel.read(buffer)
                    if (count < 0) break
                    if (count == 0) unavailable()
                }
            }
            if (buffer.position() > PolicyOwnerBounds.MAX_POLICY_BYTES || buffer.position().toLong() != before.size()) unavailable()
            val after = attributes(document) ?: unavailable()
            if (!after.isRegularFile || after.isSymbolicLink || after.size() != before.size() ||
                after.lastModifiedTime() != before.lastModifiedTime() || after.fileKey() != before.fileKey()) unavailable()
            ensureNoStaging(staging)
            requireDirectory(nativeBase)
            if (nativeBase.canonicalFile != base || document.canonicalFile != document) unavailable()
            requireAvailable()
            buffer.flip()
            Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).decode(buffer).toString()
        }
    } catch (_: Exception) {
        throw BridgeException.StorageUnavailable()
    }

    fun hasDeviceKeys(): Boolean = try {
        requireAvailable()
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val aliases = store.aliases()
        var examined = 0
        var found = false
        while (aliases.hasMoreElements()) {
            if (examined >= PolicyOwnerBounds.MAX_KEY_ALIASES) throw BridgeException.NativeUnavailable()
            examined += 1
            val alias = aliases.nextElement()
            if (alias.length > 2048) throw BridgeException.NativeUnavailable()
            // A malformed/partial alias in our namespace still prevents a fresh
            // bootstrap. No key is obtained, created, signed, exported or deleted.
            if (ControllerLibraryPolicy.isControllerAlias(alias)) { found = true; break }
        }
        requireAvailable()
        found
    } catch (_: Exception) {
        throw BridgeException.NativeUnavailable()
    }

    private fun requireAvailable() {
        if (Looper.myLooper() == Looper.getMainLooper() || application.isDeviceProtectedStorage ||
            application.getSystemService(UserManager::class.java)?.isUserUnlocked != true) unavailable()
    }
    private fun attributes(file: File): BasicFileAttributes? = try {
        Files.readAttributes(file.toPath(), BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
    } catch (_: NoSuchFileException) { null }
    private fun requireDirectory(file: File) {
        val attrs = attributes(file) ?: unavailable()
        if (!file.isAbsolute || !attrs.isDirectory || attrs.isSymbolicLink) unavailable()
    }
    private fun ensureNoStaging(staging: File) { if (attributes(staging) != null) unavailable() }
    private fun unavailable(): Nothing = throw BridgeException.StorageUnavailable()
    override fun toString(): String = "LegacyPolicyObservation(native_read_only)"
}
