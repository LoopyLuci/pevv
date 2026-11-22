package dev.pevv.app.ui

import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext

private val Cyan = Color(0xFF0EA5C6)
private val Violet = Color(0xFFC44DD4)

private val Light = lightColorScheme(primary = Color(0xFF076D84), secondary = Color(0xFF8A2F98), tertiary = Cyan)
private val Dark = darkColorScheme(primary = Color(0xFF67E8F9), secondary = Color(0xFFE879F9), tertiary = Violet, background = Color(0xFF0B1226), surface = Color(0xFF0B1226))

/** Brand colours (the padlock's cyan and violet) with the system dynamic colours where available. */
@Composable
fun PevvTheme(content: @Composable () -> Unit) {
    val dark = isSystemInDarkTheme()
    val ctx = LocalContext.current
    val scheme = when {
        Build.VERSION.SDK_INT >= 31 -> if (dark) dynamicDarkColorScheme(ctx) else dynamicLightColorScheme(ctx)
        dark -> Dark
        else -> Light
    }
    MaterialTheme(colorScheme = scheme, content = content)
}
