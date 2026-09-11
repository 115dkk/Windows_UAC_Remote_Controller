// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.pairing

import android.graphics.ImageFormat
import android.os.Looper
import android.util.Size
import androidx.camera.core.Camera
import androidx.camera.core.CameraSelector
import androidx.camera.core.CameraState
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import androidx.camera.core.Preview
import androidx.camera.core.UseCase
import androidx.camera.core.resolutionselector.ResolutionSelector
import androidx.camera.core.resolutionselector.ResolutionStrategy
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.core.content.ContextCompat
import androidx.lifecycle.Observer
import dev.dkk115.uacremote.MainActivity
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/** One original-Activity camera binding. No unbindAll, recording, image files or QR logging. */
internal class PairingCameraSession(
    private val activity: MainActivity,
    private val previewView: PreviewView,
    private val current: () -> Boolean,
    private val scanning: () -> Unit,
    private val decoded: (OfflineQrResult) -> Unit,
    private val unavailable: () -> Unit,
    private val released: () -> Unit,
) {
    private val main = ContextCompat.getMainExecutor(activity)
    private val stopped = AtomicBoolean(false)
    private val claimed = AtomicBoolean(false)
    private val failureQueued = AtomicBoolean(false)
    private val uncertain = AtomicBoolean(false)
    private val decoder = OfflineQrDecoder()
    private var providerPending = false // main only
    private var decoderStopped = false // main only
    private var releaseReported = false
    private var provider: ProcessCameraProvider? = null
    private var preview: Preview? = null
    private var analysis: ImageAnalysis? = null
    private var camera: Camera? = null
    private var scanningReported = false
    private val cameraObserver = Observer<CameraState> { value ->
        if (!stopped.get()) {
            if (value.error != null) fail()
            else if (value.type == CameraState.Type.OPEN && current() && !scanningReported) {
                scanningReported = true; scanning()
            }
        }
    }
    private val worker = object : ThreadPoolExecutor(1, 1, 0L, TimeUnit.MILLISECONDS,
        ArrayBlockingQueue<Runnable>(1), { work -> Thread(work, "uac-offline-qr").apply { isDaemon = true } }, ThreadPoolExecutor.AbortPolicy()) {
        override fun terminated() {
            super.terminated()
            onMain { decoderStopped = true; finishRelease() }
        }
    }

    fun start() {
        check(Looper.myLooper() == Looper.getMainLooper())
        if (stopped.get() || !current()) { close(); return }
        providerPending = true
        try {
            val future = ProcessCameraProvider.getInstance(activity)
            future.addListener({
                providerPending = false
                if (stopped.get()) { finishRelease(); return@addListener }
                try {
                    if (!current()) { close(); return@addListener }
                    val ownedProvider = future.get()
                    provider = ownedProvider
                    if (!ownedProvider.hasCamera(CameraSelector.DEFAULT_BACK_CAMERA)) { fail(); return@addListener }
                    val rotation = activity.display?.rotation ?: run { fail(); return@addListener }
                    val ownedPreview = Preview.Builder().setTargetRotation(rotation).build()
                    val ownedAnalysis = ImageAnalysis.Builder()
                        .setOutputImageFormat(ImageAnalysis.OUTPUT_IMAGE_FORMAT_YUV_420_888)
                        .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                        .setResolutionSelector(ResolutionSelector.Builder().setResolutionStrategy(
                            ResolutionStrategy(Size(1280, 720), ResolutionStrategy.FALLBACK_RULE_CLOSEST_LOWER_THEN_HIGHER)).build())
                        .setTargetRotation(rotation).build()
                    // Retain exact use cases before binding may partially succeed.
                    preview = ownedPreview; analysis = ownedAnalysis
                    ownedPreview.setSurfaceProvider(previewView.surfaceProvider)
                    ownedAnalysis.setAnalyzer(worker, ::analyze)
                    if (!current()) { close(); return@addListener }
                    camera = ownedProvider.bindToLifecycle(activity, CameraSelector.DEFAULT_BACK_CAMERA, ownedPreview, ownedAnalysis)
                    camera?.cameraInfo?.cameraState?.observe(activity, cameraObserver)
                    if (!current() || stopped.get()) close()
                } catch (_: Exception) { fail() }
            }, main)
        } catch (_: Exception) { providerPending = false; fail() }
    }

    private fun analyze(image: ImageProxy) {
        var luminance: ByteArray? = null
        var result: OfflineQrResult = OfflineQrResult.Absent
        var failed = false
        try {
            if (stopped.get() || claimed.get()) return
            if (image.format != ImageFormat.YUV_420_888 || image.planes.isEmpty()) { analyzerFailed(); return }
            val plane = image.planes[0]
            val pixels = QrLuminance.copy(image.width, image.height, plane.rowStride, plane.pixelStride,
                image.imageInfo.rotationDegrees, plane.buffer)
            if (pixels == null) { analyzerFailed(); return }
            luminance = pixels
            result = decoder.decode(pixels, image.width, image.height)
        } catch (_: Exception) { failed = true }
        finally {
            luminance?.fill(0)
            try { image.close() } catch (_: Exception) { uncertain.set(true); failed = true; analyzerFailed() }
        }
        // No decoded value is published until this owned image was closed.
        if (failed) analyzerFailed()
        else if (!stopped.get() && result !== OfflineQrResult.Absent && claimed.compareAndSet(false, true)) {
            val observed = result
            onMain {
                if (!stopped.get() && current()) {
                    // A real delivered/closed camera image may precede the
                    // CameraState observer on main. Binding acceptance alone
                    // never produced this transition.
                    if (!scanningReported) { scanningReported = true; scanning() }
                    decoded(observed)
                } else close()
            }
        }
    }

    private fun analyzerFailed() {
        claimed.set(true)
        if (failureQueued.compareAndSet(false, true)) onMain(::fail)
    }

    fun rotationChanged() {
        if (stopped.get()) return
        val rotation = activity.display?.rotation ?: run { fail(); return }
        preview?.targetRotation = rotation; analysis?.targetRotation = rotation
    }

    private fun fail() {
        if (stopped.get()) return
        close()
        unavailable()
    }

    fun close() {
        check(Looper.myLooper() == Looper.getMainLooper())
        if (!stopped.compareAndSet(false, true)) return
        try {
            camera?.cameraInfo?.cameraState?.removeObserver(cameraObserver)
            analysis?.clearAnalyzer()
            val owned = listOfNotNull<UseCase>(preview, analysis).toTypedArray()
            if (owned.isNotEmpty()) provider?.unbind(*owned)
            camera = null; preview = null; analysis = null; provider = null
        } catch (_: Exception) { uncertain.set(true) }
        // Let already queued analyzer callbacks close their images; never discard
        // tasks with shutdownNow or wait for a decoder/native callback on main.
        worker.shutdown()
        finishRelease()
    }

    private fun finishRelease() {
        if (stopped.get() && decoderStopped && !providerPending && !uncertain.get() && !releaseReported) {
            releaseReported = true; released()
        }
    }
    private fun onMain(action: () -> Unit) {
        try { main.execute { action() } } catch (_: Exception) { uncertain.set(true); stopped.set(true); worker.shutdown() }
    }
    override fun toString(): String = "PairingCameraSession([redacted])"
}
