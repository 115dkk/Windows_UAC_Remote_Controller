// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.background

import android.app.Application
import android.os.Looper
import java.io.File
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.attribute.BasicFileAttributes

/** No generated/JNA class is referenced until this packaged-only guard completes. */
internal object PackagedControllerLibrary {
    private enum class State { NEW, READY, FAILED }
    private var state = State.NEW

    @Synchronized fun prepare(application: Application) {
        check(Looper.myLooper() != Looper.getMainLooper())
        check(state != State.FAILED)
        if (state == State.READY) return
        state = State.FAILED
        val names = ArrayList<String>()
        val properties = System.getProperties()
        synchronized(properties) {
            if (properties.size > 1024) throw IllegalStateException("Native library configuration unavailable")
            for (key in properties.keys) {
                names.add(key as? String ?: throw IllegalStateException("Native library configuration unavailable"))
            }
        }
        check(ControllerLibraryPolicy.permitsInitialProperties(names))
        val nativePath = application.applicationInfo.nativeLibraryDir
        check(nativePath.isNotEmpty() && nativePath.length <= 4096 && nativePath.none { it.code < 32 })
        val nativeDirectory = File(nativePath).canonicalFile
        check(File(nativePath).isAbsolute && nativeDirectory.isAbsolute)
        val directoryAttributes = Files.readAttributes(nativeDirectory.toPath(), BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
        check(directoryAttributes.isDirectory && !directoryAttributes.isSymbolicLink)
        // ROOT packages extracted immutable arm64 libraries. Missing or linked
        // libraries fail here, without attempting an external/classpath fallback.
        for (name in listOf("libuac_android_controller.so", "libjnidispatch.so")) {
            val library = File(nativeDirectory, name)
            val attributes = Files.readAttributes(library.toPath(), BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
            check(attributes.isRegularFile && !attributes.isSymbolicLink && attributes.size() > 0)
            check(library.canonicalFile == library && library.parentFile == nativeDirectory)
        }
        // Only the Android package/classloader location is permitted. JNA's
        // temporary extraction and arbitrary classpath fallback are disabled.
        System.setProperty("jna.nounpack", "true")
        System.setProperty("jna.noclasspath", "true")
        System.setProperty("jna.library.path", nativeDirectory.path)
        System.setProperty("jna.platform.library.path", nativeDirectory.path)
        System.setProperty("jna.boot.library.path", nativeDirectory.path)
        Thread.currentThread().contextClassLoader = application.classLoader
        // Load through the package classloader after checking extracted files;
        // no downloaded library, cache path or generated override is used.
        System.loadLibrary(ControllerLibraryPolicy.LIBRARY)
        state = State.READY
    }
}
