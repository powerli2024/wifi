package dev.proxyaudit.android

import android.content.Context
import android.view.View
import android.widget.LinearLayout
import android.widget.TextView
import com.google.android.material.button.MaterialButton
import com.google.android.material.card.MaterialCardView

/** Shared theme roles; all controls remain local and have no networking behavior. */
internal object MaterialUi {
    fun dp(context: Context, value: Int) = (value * context.resources.displayMetrics.density).toInt()
    fun button(context: Context, label: String, primary: Boolean = false, action: () -> Unit) =
        MaterialButton(context, null, if (primary) com.google.android.material.R.attr.materialButtonStyle
            else com.google.android.material.R.attr.materialButtonOutlinedStyle).apply {
            text = label; isAllCaps = false; textSize = 14f; minHeight = dp(context, 52)
            isSaveEnabled = false; setPadding(dp(context, 16), dp(context, 8), dp(context, 16), dp(context, 8))
            setOnClickListener { action() }
            layoutParams = LinearLayout.LayoutParams(-1, -2).apply { setMargins(0, dp(context, 4), 0, dp(context, 4)) }
        }
    fun card(context: Context, parent: LinearLayout, title: String, text: String): TextView {
        val card = MaterialCardView(context).apply {
            radius = dp(context, 12).toFloat(); cardElevation = 0f
            setCardBackgroundColor(context.getColor(R.color.primary_container))
            strokeWidth = 0; isSaveEnabled = false
            layoutParams = LinearLayout.LayoutParams(-1, -2).apply { setMargins(0, dp(context, 8), 0, dp(context, 8)) }
        }
        val content = TextView(context).apply {
            this.text = context.getString(R.string.card_content, title, text); textSize = 16f; setTextColor(context.getColor(R.color.on_primary_container))
            setPadding(dp(context, 16), dp(context, 16), dp(context, 16), dp(context, 16))
            isSaveEnabled = false; setTextIsSelectable(true)
            importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO
        }
        card.addView(content); parent.addView(card)
        return content
    }
}
