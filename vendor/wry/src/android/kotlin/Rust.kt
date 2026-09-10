// Copyright 2020-2023 Tauri Programme within The Commons Conservancy
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

@file:Suppress("unused")

package {{package}}

import android.content.Intent
import android.webkit.WebView
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse

object Rust {
    init {
        System.loadLibrary("{{library}}")
    }

    @JvmStatic external fun onActivityCreate(activity: WryActivity)
    @JvmStatic external fun onActivityDestroy(activity: WryActivity)
    @JvmStatic external fun onActivitySaveInstanceState()
    @JvmStatic external fun onActivityLowMemory()
    @JvmStatic external fun onWindowFocusChanged(activity: WryActivity, focus: Boolean)
    @JvmStatic external fun onNewIntent(intent: Intent)

    @JvmStatic external fun create()
    @JvmStatic external fun start()
    @JvmStatic external fun resume()
    @JvmStatic external fun pause()
    @JvmStatic external fun stop()

    @JvmStatic external fun wryCreate()
    @JvmStatic external fun onWebviewDestroy(activity: WryActivity, webviewId: String)

    @JvmStatic external fun ipc(webView: WebView, webviewId: String, url: String, message: String)
    @JvmStatic external fun isCurrentWebView(webView: WebView, webviewId: String): Boolean

    @JvmStatic external fun assetLoaderDomain(webView: WebView, webviewId: String): String
    @JvmStatic external fun withAssetLoader(webView: WebView, webviewId: String): Boolean
    @JvmStatic external fun handleRequest(webView: WebView, webviewId: String, request: WebResourceRequest, isDocumentStartScriptEnabled: Boolean): WebResourceResponse?
    @JvmStatic external fun shouldOverride(webView: WebView, webviewId: String, url: String): Boolean
    @JvmStatic external fun onPageLoading(webView: WebView, webviewId: String, url: String)
    @JvmStatic external fun onPageLoaded(webView: WebView, webviewId: String, url: String)
    @JvmStatic external fun onEval(webView: WebView, webviewId: String, id: Int, result: String)

    @JvmStatic external fun handleReceivedTitle(webView: WebView, webviewId: String, title: String)
}
