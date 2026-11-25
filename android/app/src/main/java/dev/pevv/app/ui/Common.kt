package dev.pevv.app.ui

import android.content.Context
import android.graphics.Bitmap
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.runtime.DisposableEffect
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import dev.pevv.app.R
import dev.pevv.app.core.DecryptError
import dev.pevv.app.core.TransferError
import dev.pevv.app.pevv
import dev.pevv.app.security.Clip
import dev.pevv.app.store.VaultController
import dev.pevv.app.sync.SyncError

/** Human text for an error. Technical detail is never shown; secrets are never in these strings. */
@Composable
fun errorText(e: Throwable?): String {
    val ctx = LocalContext.current
    return e?.let { errorString(ctx, it) } ?: ""
}

fun errorString(ctx: Context, e: Throwable): String {
    val id = when (e) {
        is VaultController.UserError -> when (e.code) {
            "rate-limited" -> return ctx.getString(R.string.err_rate_limited, e.message ?: "?")
            "bad-code" -> R.string.err_bad_code
            "wrong-key-file" -> R.string.err_wrong_key_file
            "bad-key-file" -> R.string.err_bad_key_file
            "no-usb-slot" -> R.string.err_no_usb_slot
            "device-revoked" -> R.string.err_device_revoked
            "locked" -> R.string.err_locked
            else -> R.string.err_generic
        }
        is DecryptError -> R.string.err_wrong_secret
        is TransferError -> when (e.code) {
            "qr-expired" -> R.string.err_qr_expired
            "qr-incomplete" -> R.string.err_qr_incomplete
            "qr-too-big" -> R.string.err_qr_too_big
            else -> R.string.err_qr_damaged
        }
        is SyncError -> when (e.code) {
            "qr-nosync", "not-configured" -> R.string.err_no_sync
            "offline" -> R.string.err_offline
            "rate-limited" -> R.string.err_rate_limited_server
            else -> R.string.err_sync_failed
        }
        is IllegalArgumentException -> return e.message?.takeIf { it.length < 140 && !it.contains("key", true) } ?: ctx.getString(R.string.err_generic)
        else -> R.string.err_generic
    }
    return ctx.getString(id)
}

@Composable
fun Page(modifier: Modifier = Modifier, content: @Composable androidx.compose.foundation.layout.ColumnScope.() -> Unit) {
    Column(modifier.verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) { content() }
}

@Composable
fun SecretField(
    value: String, onChange: (String) -> Unit, label: String, modifier: Modifier = Modifier, imeNumber: Boolean = false, singleLine: Boolean = true,
    supporting: String? = null,
) {
    var show by remember { mutableStateOf(false) }
    val showDesc = stringResource(if (show) R.string.hide else R.string.show)
    OutlinedTextField(
        value = value, onValueChange = onChange, label = { Text(label) }, singleLine = singleLine, modifier = modifier.fillMaxWidth(),
        visualTransformation = if (show) VisualTransformation.None else PasswordVisualTransformation(),
        keyboardOptions = KeyboardOptions(keyboardType = if (imeNumber) KeyboardType.NumberPassword else KeyboardType.Password, autoCorrect = false),
        supportingText = supporting?.let { { Text(it) } },
        trailingIcon = { TextButton(onClick = { show = !show }, modifier = Modifier.semantics { contentDescription = showDesc }) { Text(showDesc) } },
    )
}

@Composable
fun SectionTitle(text: String) {
    Text(text, style = MaterialTheme.typography.titleMedium, color = MaterialTheme.colorScheme.primary, modifier = Modifier.padding(top = 8.dp))
}

@Composable
fun InfoCard(text: String, warn: Boolean = false) {
    Card(colors = CardDefaults.cardColors(containerColor = if (warn) MaterialTheme.colorScheme.errorContainer else MaterialTheme.colorScheme.secondaryContainer), modifier = Modifier.fillMaxWidth()) {
        Row(Modifier.padding(12.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Icon(if (warn) Icons.Filled.Warning else Icons.Filled.Lock, contentDescription = null, modifier = Modifier.size(20.dp))
            Text(text, style = MaterialTheme.typography.bodyMedium)
        }
    }
}

@Composable
fun Busy(text: String? = null) {
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        CircularProgressIndicator(Modifier.size(20.dp), strokeWidth = 2.dp)
        if (text != null) Text(text)
    }
}

@Composable
fun ConfirmDialog(title: String, text: String, confirm: String, onConfirm: () -> Unit, onDismiss: () -> Unit, danger: Boolean = false) {
    AlertDialog(
        onDismissRequest = onDismiss, title = { Text(title) }, text = { Text(text) },
        confirmButton = { TextButton(onClick = onConfirm) { Text(confirm, color = if (danger) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary) } },
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) } },
    )
}

/** Copy a secret to the clipboard marked sensitive; it clears itself after the delay set in Settings. */
fun copySecret(ctx: Context, label: String, value: String) {
    Clip.copySensitive(ctx, label, value, ctx.pevv.prefs.clipboardClearSeconds)
}

@Composable
fun PrimaryButton(text: String, onClick: () -> Unit, modifier: Modifier = Modifier, enabled: Boolean = true) {
    Button(onClick = onClick, enabled = enabled, modifier = modifier.fillMaxWidth(), contentPadding = PaddingValues(14.dp)) { Text(text) }
}

@Composable
fun SecondaryButton(text: String, onClick: () -> Unit, modifier: Modifier = Modifier, enabled: Boolean = true) {
    OutlinedButton(onClick = onClick, enabled = enabled, modifier = modifier.fillMaxWidth(), contentPadding = PaddingValues(14.dp)) { Text(text) }
}

@Composable
fun Done(text: String) {
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Icon(Icons.Filled.Check, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
        Text(text)
    }
}

/**
 * A QR code as an image with a text description for screen readers. Black on white even in dark mode, scales to
 * the width available, and while it is on screen the display goes to full brightness and stays on.
 */
@Composable
fun QrImage(text: String, description: String, size: Int = 1024, modifier: Modifier = Modifier) {
    val bmp = remember(text, size) { qrBitmap(text, size) }
    KeepBright()
    Image(
        bmp.asImageBitmap(),
        contentDescription = description,
        modifier = modifier.fillMaxWidth().aspectRatio(1f).background(androidx.compose.ui.graphics.Color.White),
        filterQuality = androidx.compose.ui.graphics.FilterQuality.None,
    )
}

/** Full screen brightness and no screen timeout while this is in the composition, restored after. */
@Composable
fun KeepBright() {
    val ctx = LocalContext.current
    DisposableEffect(ctx) {
        var c: android.content.Context? = ctx
        while (c is android.content.ContextWrapper && c !is android.app.Activity) c = c.baseContext
        val window = (c as? android.app.Activity)?.window
        val before = window?.attributes?.screenBrightness
        window?.let {
            it.attributes = it.attributes.also { a -> a.screenBrightness = android.view.WindowManager.LayoutParams.BRIGHTNESS_OVERRIDE_FULL }
            it.addFlags(android.view.WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        }
        onDispose {
            window?.let {
                it.clearFlags(android.view.WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
                it.attributes = it.attributes.also { a -> a.screenBrightness = before ?: android.view.WindowManager.LayoutParams.BRIGHTNESS_OVERRIDE_NONE }
            }
        }
    }
}

fun qrBitmap(text: String, size: Int): Bitmap {
    val (side, px) = dev.pevv.app.core.QrEncode.render(text, size)
    return Bitmap.createBitmap(px, side, side, Bitmap.Config.ARGB_8888)
}
