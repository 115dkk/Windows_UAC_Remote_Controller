// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.pairing

import android.content.Context
import android.content.res.ColorStateList
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.camera.view.PreviewView
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import com.google.android.material.button.MaterialButton
import dev.dkk115.uacremote.AppLanguage
import dev.dkk115.uacremote.R

/** App-owned controls only. Fixture rendering needs no QR/camera or FLAG_SECURE exception. */
internal class PairingScannerView(
    context: Context,
    onClose: () -> Unit,
    onPermission: () -> Unit,
    onConfirm: () -> Unit = {},
    onReject: () -> Unit = {},
) : ScrollView(context) {
    // The dialog already owns a frozen localized Context. Select from that
    // snapshot, not a fresh preference read that could mix languages mid-flow.
    private val bodyTypeface = context.resources.getFont(when (
        AppLanguage.match(context.resources.configuration.locales[0].toLanguageTag())
    ) {
        "ko" -> R.font.noto_sans_kr
        "ja" -> R.font.noto_sans_jp
        "zh-Hans" -> R.font.noto_sans_sc
        "zh-Hant" -> R.font.noto_sans_tc
        "ar" -> R.font.noto_sans_arabic
        else -> R.font.noto_sans
    })
    private val latinTypeface = context.resources.getFont(R.font.noto_sans)
    private val column = LinearLayout(context).apply { orientation = LinearLayout.VERTICAL }
    private val heading = TextView(context).apply {
        setText(R.string.pairing_scanner_title); textSize = 24f
        typeface = Typeface.create(bodyTypeface, Typeface.BOLD)
        includeFontPadding = true
        setTextColor(context.getColor(R.color.pairing_scanner_text))
        isAccessibilityHeading = true; isFocusableInTouchMode = true
    }
    private val message = TextView(context).apply {
        id = R.id.pairing_scanner_message
        textSize = 17f; setTextColor(context.getColor(R.color.pairing_scanner_text))
        typeface = bodyTypeface; includeFontPadding = true
        accessibilityLiveRegion = View.ACCESSIBILITY_LIVE_REGION_POLITE
        setLineSpacing(dp(4).toFloat(), 1f)
    }
    private val detail = TextView(context).apply {
        textSize = 16f; setTextColor(context.getColor(R.color.pairing_scanner_muted))
        typeface = bodyTypeface; includeFontPadding = true
    }
    private val previewContainer = FrameLayout(context).apply {
        background = GradientDrawable().apply {
            setColor(context.getColor(R.color.pairing_scanner_surface)); cornerRadius = dp(16).toFloat()
        }
        clipToOutline = true
        importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO_HIDE_DESCENDANTS
    }
    private val code = TextView(context).apply {
        id = R.id.pairing_scanner_code
        textSize = 32f; letterSpacing = 0.12f; fontFeatureSettings = "tnum"
        // Visual comparison bytes stay ASCII with a bundled Latin face even
        // when the surrounding copy and spoken digit names are Arabic.
        typeface = Typeface.create(latinTypeface, Typeface.BOLD)
        includeFontPadding = true
        setTextColor(context.getColor(R.color.pairing_scanner_text))
        gravity = Gravity.CENTER
        textDirection = View.TEXT_DIRECTION_LTR
    }
    private val confirmButton = button(R.string.pairing_scanner_confirm, true, onConfirm).apply { id = R.id.pairing_scanner_confirm }
    private val rejectButton = button(R.string.pairing_scanner_reject, false, onReject).apply { id = R.id.pairing_scanner_reject }
    private val permissionButton = button(R.string.pairing_scanner_allow_camera, true, onPermission)
    private val closeButton = button(R.string.pairing_scanner_close, false, onClose).apply { id = R.id.pairing_scanner_close }

    init {
        id = R.id.pairing_scanner_root
        layoutDirection = resources.configuration.layoutDirection
        textDirection = View.TEXT_DIRECTION_LOCALE
        isFillViewport = true
        setBackgroundColor(context.getColor(R.color.pairing_scanner_bg))
        addView(column, LayoutParams(LayoutParams.MATCH_PARENT, LayoutParams.WRAP_CONTENT))
        column.setPadding(dp(20), dp(20), dp(20), dp(20))
        addContent(heading, 0)
        addContent(message, 20)
        column.addView(previewContainer, LinearLayout.LayoutParams(LayoutParams.MATCH_PARENT, dp(260)).apply { topMargin = dp(20) })
        addContent(detail, 16)
        addContent(code, 24)
        addContent(confirmButton, 24)
        addContent(rejectButton, 12)
        addContent(permissionButton, 24)
        addContent(closeButton, 12)
        ViewCompat.setOnApplyWindowInsetsListener(this) { _, insets ->
            val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout())
            setPadding(bars.left, bars.top, bars.right, bars.bottom)
            insets
        }
        render(PairingScannerState.PREPARING)
    }

    private fun button(label: Int, primary: Boolean, action: () -> Unit) = MaterialButton(context).apply {
        setText(label); isAllCaps = false; textSize = 16f; minHeight = dp(48)
        typeface = bodyTypeface; includeFontPadding = true
        insetTop = 0; insetBottom = 0; cornerRadius = dp(16); stateListAnimator = null
        setPadding(dp(16), dp(12), dp(16), dp(12))
        backgroundTintList = ColorStateList.valueOf(context.getColor(if (primary) R.color.pairing_scanner_accent else R.color.pairing_scanner_surface))
        rippleColor = ColorStateList.valueOf(context.getColor(R.color.pairing_scanner_ripple))
        strokeWidth = dp(2)
        strokeColor = ColorStateList(arrayOf(intArrayOf(android.R.attr.state_focused), intArrayOf()),
            intArrayOf(context.getColor(R.color.pairing_scanner_accent), context.getColor(if (primary) R.color.pairing_scanner_accent else R.color.pairing_scanner_surface)))
        setTextColor(context.getColor(if (primary) R.color.pairing_scanner_on_accent else R.color.pairing_scanner_text))
        setOnClickListener { action() }
    }

    private fun addContent(view: View, margin: Int) {
        column.addView(view, LinearLayout.LayoutParams(LayoutParams.MATCH_PARENT, LayoutParams.WRAP_CONTENT).apply { topMargin = dp(margin) })
    }

    fun attachPreview(preview: PreviewView) {
        previewContainer.addView(preview, FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT))
    }
    fun removePreview() { previewContainer.removeAllViews() }
    fun focusHeading() { heading.requestFocus() }

    fun render(
        state: PairingScannerState,
        permissionSettingsAvailable: Boolean = false,
        comparisonCode: String? = null,
        failureDetail: Int? = null,
    ) {
        val displayedState = PairingScannerCopy.resolvedState(state, comparisonCode)
        message.setText(when (displayedState) {
            PairingScannerState.PREPARING -> R.string.pairing_scanner_preparing
            PairingScannerState.PERMISSION_PENDING -> R.string.pairing_scanner_permission_pending
            PairingScannerState.PERMISSION_DENIED -> R.string.pairing_scanner_permission_denied
            PairingScannerState.PERMISSION_SETTINGS -> R.string.pairing_scanner_permission_settings
            PairingScannerState.CAMERA_UNAVAILABLE -> R.string.pairing_scanner_camera_unavailable
            PairingScannerState.UNAVAILABLE -> R.string.pairing_scanner_unavailable
            PairingScannerState.SCANNING -> R.string.pairing_scanner_scanning
            PairingScannerState.READING -> R.string.pairing_scanner_reading
            PairingScannerState.READ -> R.string.pairing_scanner_read
            PairingScannerState.CONNECTING -> R.string.pairing_scanner_connecting
            PairingScannerState.COMPARE -> R.string.pairing_scanner_compare
            PairingScannerState.WAITING_PC -> R.string.pairing_scanner_waiting_pc
            PairingScannerState.ENROLLED -> R.string.pairing_scanner_enrolled
            PairingScannerState.FAILED -> R.string.pairing_scanner_failed
            PairingScannerState.INVALID -> R.string.pairing_scanner_invalid
            PairingScannerState.EXPIRED -> R.string.pairing_scanner_expired
            PairingScannerState.CLOSED -> R.string.pairing_scanner_closed
        })
        previewContainer.visibility = if (displayedState in setOf(PairingScannerState.PREPARING, PairingScannerState.SCANNING)) VISIBLE else GONE
        val detailText = when (displayedState) {
            PairingScannerState.READ -> R.string.pairing_scanner_read_detail
            PairingScannerState.CONNECTING -> R.string.pairing_scanner_connecting_detail
            PairingScannerState.WAITING_PC -> R.string.pairing_scanner_waiting_pc_detail
            PairingScannerState.ENROLLED -> R.string.pairing_scanner_enrolled_detail
            PairingScannerState.FAILED -> failureDetail ?: R.string.pairing_scanner_failed_unavailable
            else -> null
        }
        detail.text = detailText?.let { context.getString(it) }.orEmpty()
        detail.visibility = if (detailText != null) VISIBLE else GONE
        val comparing = displayedState == PairingScannerState.COMPARE
        code.text = if (comparing) PairingScannerCopy.groupedCode(requireNotNull(comparisonCode)) else ""
        code.contentDescription = if (comparing) PairingScannerCopy.codeDescription(requireNotNull(comparisonCode),
            context.getString(R.string.pairing_digit_names).split(',')) else null
        code.visibility = if (comparing) VISIBLE else GONE
        confirmButton.visibility = if (comparing) VISIBLE else GONE
        rejectButton.visibility = if (comparing) VISIBLE else GONE
        permissionButton.visibility = if (displayedState == PairingScannerState.PERMISSION_DENIED ||
            (displayedState == PairingScannerState.PERMISSION_SETTINGS && permissionSettingsAvailable)) VISIBLE else GONE
        permissionButton.setText(if (displayedState == PairingScannerState.PERMISSION_SETTINGS) R.string.pairing_scanner_open_permissions else R.string.pairing_scanner_allow_camera)
    }

    override fun onSizeChanged(w: Int, h: Int, oldw: Int, oldh: Int) {
        super.onSizeChanged(w, h, oldw, oldh)
        val height = (h * 0.38f).toInt().coerceIn(dp(160), dp(320))
        if (previewContainer.layoutParams.height != height) previewContainer.layoutParams = previewContainer.layoutParams.apply { this.height = height }
    }
    private fun dp(value: Int): Int = (value * resources.displayMetrics.density + 0.5f).toInt()
}
