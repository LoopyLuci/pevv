package dev.pevv.app.ui

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.provider.Settings
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Checkbox
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.ui.text.input.KeyboardType
import dev.pevv.app.BuildConfig
import dev.pevv.app.R
import dev.pevv.app.core.Bytes
import dev.pevv.app.core.Devices
import dev.pevv.app.core.Import
import dev.pevv.app.core.ImportResult
import dev.pevv.app.core.Json
import dev.pevv.app.core.Recovery
import dev.pevv.app.core.Entry
import dev.pevv.app.core.Totp
import dev.pevv.app.core.TotpConfig
import dev.pevv.app.core.VaultEngine
import dev.pevv.app.core.jstr
import dev.pevv.app.core.with
import dev.pevv.app.passkey.PasskeyAuth
import dev.pevv.app.pevv
import dev.pevv.app.security.BiometricVault
import dev.pevv.app.store.VaultController
import dev.pevv.app.sync.SyncConfig
import kotlinx.serialization.json.JsonObject

enum class SettingsRoute { MAIN, DEVICES, RECOVERY, IMPORT, FACTORS, SYNC }

@Composable
private fun Row2(label: String, content: @Composable () -> Unit) {
    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        Text(label, Modifier.weight(1f))
        content()
    }
}

@Composable
private fun Choice(options: List<Pair<String, Int>>, current: Int, onPick: (Int) -> Unit) {
    Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
        for ((label, v) in options) FilterChip(selected = current == v, onClick = { onPick(v) }, label = { Text(label) })
    }
}

fun saveText(ctx: android.content.Context, uri: Uri, text: String) {
    ctx.contentResolver.openOutputStream(uri, "wt")!!.use { it.write(text.toByteArray(Charsets.UTF_8)) }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(onBack: () -> Unit, onShare: () -> Unit, onRoute: (SettingsRoute) -> Unit) {
    val ctx = LocalContext.current
    val app = ctx.pevv
    val prefs = app.prefs
    val ctl = app.vault
    var lockMin by remember { mutableStateOf(prefs.lockMinutes) }
    var idle by remember { mutableStateOf(prefs.idleSeconds) }
    var clip by remember { mutableStateOf(prefs.clipboardClearSeconds) }
    var bio by remember { mutableStateOf(prefs.biometricOn && app.bio.enrolled) }
    var erase by remember { mutableStateOf(false) }
    var lang by remember { mutableStateOf(prefs.language) }
    val op = rememberOp()
    val run = op.runner()
    val activity = ctx as? Activity

    Scaffold(topBar = { BackBar(stringResource(R.string.settings), onBack) }) { pad ->
        Page(Modifier.padding(pad)) {
            SectionTitle(stringResource(R.string.sec_security))
            Text(stringResource(R.string.auto_lock_background))
            Choice(listOf(stringResource(R.string.immediately) to 0, "1 min" to 1, "5 min" to 5, "15 min" to 15), lockMin) { lockMin = it; prefs.lockMinutes = it }
            Text(stringResource(R.string.auto_lock_idle))
            Choice(listOf("1 min" to 60, "5 min" to 300, "15 min" to 900, stringResource(R.string.never) to 0), idle) { idle = it; prefs.idleSeconds = it; ctl.touch() }
            Text(stringResource(R.string.clipboard_clear))
            Choice(listOf("15 s" to 15, "30 s" to 30, "60 s" to 60, "2 min" to 120), clip) { clip = it; prefs.clipboardClearSeconds = it }
            if (app.bio.available) {
                Row2(stringResource(R.string.biometric_unlock)) {
                    Switch(bio, { on ->
                        if (!on) { app.bio.forget(); prefs.biometricOn = false; bio = false }
                        else {
                            val key = ctl.vaultKeyCopy()
                            val id = ctl.file?.id
                            if (key != null && id != null) app.bio.enroll(key, id, ctx.getString(R.string.bio_enable_title), ctx.getString(R.string.bio_enable_subtitle), ctx.getString(R.string.cancel)) { out ->
                                key.fill(0)
                                if (out is BiometricVault.Outcome.Ok) { prefs.biometricOn = true; bio = true } else if (out is BiometricVault.Outcome.Failed) op.error = IllegalStateException(out.reason)
                            }
                        }
                    })
                }
                Text(stringResource(if (app.bio.strongBox) R.string.bio_strongbox else R.string.bio_keystore), style = MaterialTheme.typography.bodySmall)
            } else Text(stringResource(R.string.bio_unavailable), style = MaterialTheme.typography.bodySmall)
            SecondaryButton(stringResource(R.string.sec_factors), { onRoute(SettingsRoute.FACTORS) })
            SecondaryButton(stringResource(R.string.sec_recovery), { onRoute(SettingsRoute.RECOVERY) })
            HorizontalDivider()

            SectionTitle(stringResource(R.string.sec_vault))
            SecondaryButton(stringResource(R.string.sec_devices), { onRoute(SettingsRoute.DEVICES) })
            SecondaryButton(stringResource(R.string.sec_sync), { onRoute(SettingsRoute.SYNC) })
            SecondaryButton(stringResource(R.string.show_vault_qr), onShare)
            SecondaryButton(stringResource(R.string.sec_import_export), { onRoute(SettingsRoute.IMPORT) })
            HorizontalDivider()

            SectionTitle(stringResource(R.string.sec_system))
            SecondaryButton(stringResource(R.string.setup_autofill), {
                val i = Intent(Settings.ACTION_REQUEST_SET_AUTOFILL_SERVICE, Uri.parse("package:${ctx.packageName}"))
                try { ctx.startActivity(i) } catch (_: Exception) { ctx.startActivity(Intent(Settings.ACTION_SETTINGS)) }
            })
            if (Build.VERSION.SDK_INT >= 34) SecondaryButton(stringResource(R.string.setup_passkeys), {
                try { ctx.startActivity(Intent("android.settings.CREDENTIAL_PROVIDER").setData(Uri.parse("package:${ctx.packageName}"))) } catch (_: Exception) { ctx.startActivity(Intent(Settings.ACTION_SETTINGS)) }
            }) else Text(stringResource(R.string.passkeys_need_14), style = MaterialTheme.typography.bodySmall)
            Text(stringResource(R.string.language))
            Choice(listOf(stringResource(R.string.lang_system) to 0, "English" to 1, "Español" to 2), when (lang) { "en" -> 1; "es" -> 2; else -> 0 }) {
                lang = when (it) { 1 -> "en"; 2 -> "es"; else -> "" }
                prefs.language = lang
                activity?.recreate()
            }
            HorizontalDivider()
            SectionTitle(stringResource(R.string.sec_about))
            Text(stringResource(R.string.about_body, BuildConfig.VERSION_NAME))
            if (SyncConfig.rpId.isNotEmpty()) Text(stringResource(R.string.about_rp, SyncConfig.rpId), style = MaterialTheme.typography.bodySmall)
            HorizontalDivider()
            TextButton(onClick = { erase = true }) { Text(stringResource(R.string.erase_vault), color = MaterialTheme.colorScheme.error) }
            op.error?.let { Text(errorText(it), color = MaterialTheme.colorScheme.error) }
        }
    }
    if (erase) {
        var pw by remember { mutableStateOf("") }
        androidx.compose.material3.AlertDialog(
            onDismissRequest = { erase = false }, title = { Text(stringResource(R.string.erase_vault)) },
            text = { Column { Text(stringResource(R.string.erase_body)); SecretField(pw, { pw = it }, stringResource(R.string.master_password)) } },
            confirmButton = { TextButton(onClick = { run { if (ctl.reauth(pw)) { app.bio.forget(); prefs.biometricOn = false; ctl.destroyVault(); erase = false } else throw dev.pevv.app.core.DecryptError() } }) { Text(stringResource(R.string.erase), color = MaterialTheme.colorScheme.error) } },
            dismissButton = { TextButton(onClick = { erase = false }) { Text(stringResource(R.string.cancel)) } },
        )
    }
}

/* ───────────────────────── devices ───────────────────────── */

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DevicesScreen(onBack: () -> Unit) {
    val ctx = LocalContext.current
    val app = ctx.pevv
    val ctl = app.vault
    val tablet = ctx.resources.configuration.smallestScreenWidthDp >= 600
    var name by remember { mutableStateOf(app.prefs.customDeviceName) }
    var revoke by remember { mutableStateOf<String?>(null) }
    var rotated by remember { mutableStateOf<VaultController.RotateReport?>(null) }
    val op = rememberOp()
    val run = op.runner()
    val devices = ctl.meta?.devices ?: emptyList()
    Scaffold(topBar = { BackBar(stringResource(R.string.sec_devices), onBack) }) { pad ->
        Page(Modifier.padding(pad)) {
            Text(stringResource(R.string.devices_body))
            OutlinedTextField(name, { name = it }, label = { Text(stringResource(R.string.this_device_name)) }, singleLine = true, modifier = Modifier.fillMaxWidth())
            SecondaryButton(stringResource(R.string.save), { run { ctl.renameThisDevice(name, tablet) } }, enabled = name.isNotBlank() && !op.busy)
            for (d in devices) {
                val mine = d.id == app.prefs.deviceId
                Column(Modifier.fillMaxWidth()) {
                    Text(d.name + if (mine) " (" + stringResource(R.string.this_device) + ")" else "", style = MaterialTheme.typography.titleSmall)
                    Text("${d.agent} · " + stringResource(R.string.last_seen, java.text.DateFormat.getDateTimeInstance().format(java.util.Date(d.seen))), style = MaterialTheme.typography.bodySmall)
                    if (!mine) TextButton(onClick = { revoke = d.id }) { Text(stringResource(R.string.revoke), color = MaterialTheme.colorScheme.error) }
                }
                HorizontalDivider()
            }
            if (devices.isEmpty()) Text(stringResource(R.string.no_devices))
            op.error?.let { Text(errorText(it), color = MaterialTheme.colorScheme.error) }
        }
    }
    revoke?.let { id ->
        var rotate by remember { mutableStateOf(true) }
        var pw by remember { mutableStateOf("") }
        androidx.compose.material3.AlertDialog(
            onDismissRequest = { revoke = null }, title = { Text(stringResource(R.string.revoke_title)) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(stringResource(R.string.revoke_body))
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(rotate, { rotate = it })
                        Text(stringResource(R.string.remove_rotate))
                    }
                    Text(stringResource(R.string.rotate_why), style = MaterialTheme.typography.bodySmall)
                    if (rotate) SecretField(pw, { pw = it }, stringResource(R.string.rotate_password))
                }
            },
            confirmButton = {
                TextButton(enabled = !rotate || pw.isNotEmpty(), onClick = {
                    revoke = null
                    if (rotate) run { rotated = ctl.revokeAndRotate(id, pw) } else run { ctl.revokeDevice(id) }
                }) { Text(stringResource(R.string.revoke), color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = { TextButton(onClick = { revoke = null }) { Text(stringResource(R.string.cancel)) } },
        )
    }
    rotated?.let { r ->
        androidx.compose.material3.AlertDialog(
            onDismissRequest = { }, title = { Text(stringResource(R.string.rotate_new_codes)) },
            text = {
                Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(stringResource(R.string.rotate_done))
                    if (r.codes.isNotEmpty()) Text(r.codes.joinToString("\n"), style = MaterialTheme.typography.bodyMedium)
                    r.recoveryKey?.let { Text(stringResource(R.string.rotate_new_key)); Text(it, style = MaterialTheme.typography.bodySmall) }
                    if (r.dropped.isNotEmpty()) Text(stringResource(R.string.rotate_dropped, r.dropped.joinToString(", ") { it.name ?: it.type }))
                }
            },
            confirmButton = { TextButton(onClick = { rotated = null }) { Text(stringResource(R.string.rotate_saved)) } },
        )
    }
}

/* ───────────────────────── recovery ───────────────────────── */

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun RecoveryScreen(onBack: () -> Unit) {
    val ctx = LocalContext.current
    val ctl = ctx.pevv.vault
    val file = ctl.file
    val status = file?.let { VaultEngine.recoveryStatus(it) }
    var codes by remember { mutableStateOf<List<String>?>(null) }
    var key by remember { mutableStateOf<String?>(null) }
    var kitPass by remember { mutableStateOf("") }
    var kitText by remember { mutableStateOf<String?>(null) }
    val op = rememberOp()
    val run = op.runner()
    val saveKit = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/json")) { uri ->
        val t = kitText
        if (uri != null && t != null) run { saveText(ctx, uri, t); kitText = null }
    }
    Scaffold(topBar = { BackBar(stringResource(R.string.sec_recovery), onBack) }) { pad ->
        Page(Modifier.padding(pad)) {
            InfoCard(stringResource(R.string.recovery_body))
            if (status != null) Text(stringResource(R.string.recovery_status, status.codes, if (status.key) stringResource(R.string.yes) else stringResource(R.string.no)))
            SecondaryButton(stringResource(R.string.new_recovery_codes), { run { codes = ctl.newRecoveryCodes() } }, enabled = !op.busy)
            codes?.let { c ->
                InfoCard(stringResource(R.string.shown_once), warn = true)
                for (x in c) Text(x, style = MaterialTheme.typography.titleMedium)
                TextButton(onClick = { copySecret(ctx, "recovery codes", c.joinToString("\n")) }) { Text(stringResource(R.string.copy)) }
            }
            SecondaryButton(stringResource(R.string.new_recovery_key), { run { key = ctl.newRecoveryKey() } }, enabled = !op.busy)
            key?.let { k ->
                InfoCard(stringResource(R.string.shown_once), warn = true)
                Text(k, style = MaterialTheme.typography.titleMedium)
                TextButton(onClick = { copySecret(ctx, "recovery key", k) }) { Text(stringResource(R.string.copy)) }
                SectionTitle(stringResource(R.string.recovery_kit))
                Text(stringResource(R.string.kit_make_body))
                SecretField(kitPass, { kitPass = it }, stringResource(R.string.kit_passphrase))
                SecondaryButton(stringResource(R.string.save_kit_file), {
                    run {
                        kitText = Json.encodePretty(Recovery.buildKit(ctl.file!!.id, k, kitPass)) + "\n"
                        saveKit.launch("pevv-recovery-kit.json")
                    }
                }, enabled = kitPass.length >= 8 && !op.busy)
            }
            if (op.busy) Busy(stringResource(R.string.working))
            op.error?.let { Text(errorText(it), color = MaterialTheme.colorScheme.error) }
        }
    }
}

/* ───────────────────────── factors ───────────────────────── */

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun FactorsScreen(onBack: () -> Unit) {
    val ctx = LocalContext.current
    val app = ctx.pevv
    val ctl = app.vault
    val meta = ctl.meta
    var current by remember { mutableStateOf("") }
    var next by remember { mutableStateOf("") }
    var next2 by remember { mutableStateOf("") }
    var secret by remember { mutableStateOf<String?>(null) }
    var code by remember { mutableStateOf("") }
    var keyName by remember { mutableStateOf("") }
    var keyText by remember { mutableStateOf<String?>(null) }
    var keyUnlock by remember { mutableStateOf(true) }
    val op = rememberOp()
    val run = op.runner()
    val saveKey = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri ->
        val t = keyText
        if (uri != null && t != null) run { saveText(ctx, uri, t); keyText = null }
    }
    val activity = ctx as? Activity
    Scaffold(topBar = { BackBar(stringResource(R.string.sec_factors), onBack) }) { pad ->
        Page(Modifier.padding(pad)) {
            SectionTitle(stringResource(R.string.change_password))
            SecretField(current, { current = it }, stringResource(R.string.current_password))
            SecretField(next, { next = it }, stringResource(R.string.new_password))
            SecretField(next2, { next2 = it }, stringResource(R.string.confirm_password))
            PrimaryButton(stringResource(R.string.change_password), { run { ctl.changePassword(current, next); current = ""; next = ""; next2 = ""; op.message = ctx.getString(R.string.saved) } },
                enabled = current.isNotEmpty() && next.length >= 8 && next == next2 && !op.busy)
            HorizontalDivider()

            SectionTitle(stringResource(R.string.totp_gate))
            Text(stringResource(R.string.totp_gate_body))
            if (meta?.require?.totp == true) {
                Done(stringResource(R.string.totp_on))
                SecondaryButton(stringResource(R.string.turn_off), { run { ctl.setTotpGate(null) } })
            } else {
                if (secret == null) SecondaryButton(stringResource(R.string.totp_set_up), { secret = Totp.newSecret() })
                else {
                    val cfg = TotpConfig(secret!!)
                    Text(secret!!.chunked(4).joinToString(" "), style = MaterialTheme.typography.titleMedium)
                    QrImage(Totp.otpauthUri(cfg, "vault"), stringResource(R.string.totp_qr_desc), 480)
                    TextButton(onClick = { copySecret(ctx, "secret", secret!!) }) { Text(stringResource(R.string.copy)) }
                    OutlinedTextField(code, { code = it.filter(Char::isDigit).take(6) }, label = { Text(stringResource(R.string.auth_code)) }, singleLine = true, modifier = Modifier.fillMaxWidth(),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number))
                    PrimaryButton(stringResource(R.string.turn_on), {
                        run {
                            if (Totp.verify(cfg, code) == null) throw VaultController.UserError("bad-code")
                            ctl.setTotpGate(cfg); secret = null; code = ""
                        }
                    }, enabled = code.length == 6 && !op.busy)
                }
            }
            HorizontalDivider()

            SectionTitle(stringResource(R.string.usb_keys))
            Text(stringResource(R.string.usb_keys_body))
            for (g in meta?.usbKeys ?: emptyList()) Row2(g.name) { TextButton(onClick = { run { ctl.removeUsbKey(g.id) } }) { Text(stringResource(R.string.remove)) } }
            for (s in ctl.file?.slots?.filter { it.type == "usb-key" } ?: emptyList()) Row2(s.name) { TextButton(onClick = { run { ctl.removeUsbKey(s.id) } }) { Text(stringResource(R.string.remove)) } }
            OutlinedTextField(keyName, { keyName = it }, label = { Text(stringResource(R.string.key_name)) }, singleLine = true, modifier = Modifier.fillMaxWidth())
            Row2(stringResource(R.string.key_unlocks_alone)) { Switch(keyUnlock, { keyUnlock = it }) }
            SecondaryButton(stringResource(R.string.make_key_file), { run { keyText = ctl.addUsbKey(keyName, keyUnlock); saveKey.launch(".pevvkey") } }, enabled = !op.busy)
            if (!meta?.usbKeys.isNullOrEmpty()) Row2(stringResource(R.string.require_key_file)) { Switch(meta?.require?.usbKey == true, { on -> run { ctl.setRequireUsbKey(on) } }) }
            HorizontalDivider()

            SectionTitle(stringResource(R.string.passkeys))
            val recs = ctl.file?.passkeys?.mapNotNull { it as? JsonObject } ?: emptyList()
            for (r in recs) Row2((r["name"] as? kotlinx.serialization.json.JsonPrimitive)?.content ?: "passkey") {
                TextButton(onClick = { run { ctl.removePasskeyRecord((r["id"] as kotlinx.serialization.json.JsonPrimitive).content) } }) { Text(stringResource(R.string.remove)) }
            }
            if (SyncConfig.rpId.isNotEmpty() && activity != null) {
                SecondaryButton(stringResource(R.string.add_passkey), {
                    run {
                        val e = PasskeyAuth.enrol(activity, SyncConfig.rpId, ctl.file!!.id, "Android", true)
                        val credId = (e.record["id"] as kotlinx.serialization.json.JsonPrimitive).content
                        val prfMode = (e.record["mode"] as kotlinx.serialization.json.JsonPrimitive).content == "prf"
                        val salt = (e.record["prfSalt"] as? kotlinx.serialization.json.JsonPrimitive)?.takeIf { it.isString }?.content
                        // PRF output is not always returned when the passkey is made; ask for it once more.
                        val out = if (prfMode) (e.prfOutput ?: PasskeyAuth.assertPrf(activity, SyncConfig.rpId, listOf(credId to salt)).prfOutput) else null
                        if (out != null) ctl.addPrfSlot(credId, out, e.record)
                        else ctl.addPasskeyRecord(e.record.with("mode" to jstr("2fa"), "prfSalt" to dev.pevv.app.core.jnull))
                    }
                }, enabled = !op.busy)
                Text(stringResource(R.string.passkey_prf_note), style = MaterialTheme.typography.bodySmall)
            } else Text(stringResource(R.string.passkey_needs_rpid), style = MaterialTheme.typography.bodySmall)
            if (op.busy) Busy(stringResource(R.string.working))
            op.message?.let { Done(it) }
            op.error?.let { Text(errorText(it), color = MaterialTheme.colorScheme.error) }
        }
    }
}

/* ───────────────────────── sync ───────────────────────── */

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SyncScreen(onBack: () -> Unit) {
    val ctx = LocalContext.current
    val app = ctx.pevv
    val sync = app.sync
    val ctl = app.vault
    var on by remember { mutableStateOf(app.prefs.syncOn) }
    val op = rememberOp()
    val run = op.runner()
    Scaffold(topBar = { BackBar(stringResource(R.string.sec_sync), onBack) }) { pad ->
        Page(Modifier.padding(pad)) {
            if (!SyncConfig.configured) { InfoCard(stringResource(R.string.sync_not_configured)); return@Page }
            InfoCard(stringResource(R.string.sync_body))
            val acc = sync.account
            if (acc == null) SignInForm(onBack = onBack) else {
                Done(stringResource(R.string.signed_in_as, acc.email ?: ""))
                Row2(stringResource(R.string.sync_this_vault)) { Switch(on, { v -> on = v; run { sync.setSync(v) } }) }
                if (sync.lastSyncAt > 0) Text(stringResource(R.string.last_sync, java.text.DateFormat.getDateTimeInstance().format(java.util.Date(sync.lastSyncAt))), style = MaterialTheme.typography.bodySmall)
                if (sync.lastSyncAt <= 0) Text(stringResource(R.string.sync_never), style = MaterialTheme.typography.bodySmall)
                Text(stringResource(if (ctl.syncPending) R.string.sync_pending_yes else R.string.sync_pending_no), style = MaterialTheme.typography.bodySmall)
                if (ctl.needsUnlock) Text(stringResource(R.string.sync_needs_unlock), color = MaterialTheme.colorScheme.error)
                SecondaryButton(stringResource(R.string.sync_now), { run { sync.pull() } })
                SecondaryButton(stringResource(R.string.sign_out), { run { sync.signOut() } })
            }
            (ctl.syncRejection ?: sync.error)?.let { code -> Text(syncErrorText(code), color = MaterialTheme.colorScheme.error) }
            if (acc != null) SyncConflicts(ctl)
            if (op.busy) Busy()
            op.error?.let { Text(errorText(it), color = MaterialTheme.colorScheme.error) }
        }
    }
}

/** Plain-language text for a sync error code (the codes of the web client's syncStatus.ts, plus the transport ones). */
@Composable
private fun syncErrorText(code: String): String = when (code) {
    "offline" -> stringResource(R.string.sync_err_offline)
    "rate-limited" -> stringResource(R.string.sync_err_rate)
    "too-large" -> stringResource(R.string.sync_err_too_large)
    "rejected-revoked" -> stringResource(R.string.sync_err_revoked)
    "rejected-stale-key" -> stringResource(R.string.sync_err_stale_key)
    "rejected-key" -> stringResource(R.string.sync_err_key)
    "rejected-vault" -> stringResource(R.string.sync_err_vault)
    "denied", "http-401", "http-403" -> stringResource(R.string.sync_err_denied)
    "rev-regressed" -> stringResource(R.string.sync_err_regress)
    "unknown" -> stringResource(R.string.sync_err_unknown)
    else -> stringResource(R.string.sync_error, code)
}

/** Conflicts resolved by the last merges, and the versions that lost, which stay inside their items. */
@Composable
private fun SyncConflicts(ctl: VaultController) {
    var open by remember { mutableStateOf(false) }
    var kept by remember { mutableStateOf(false) }
    var values by remember { mutableStateOf(false) }
    val fmt = remember { java.text.DateFormat.getDateTimeInstance() }
    SectionTitle(stringResource(R.string.sync_conflicts_title, ctl.resolved.size))
    TextButton(onClick = { open = !open }) { Text(stringResource(if (open) R.string.hide else R.string.show)) }
    if (open) {
        if (ctl.resolved.isEmpty()) Text(stringResource(R.string.sync_conflicts_none), style = MaterialTheme.typography.bodySmall)
        for (c in ctl.resolved) {
            val title = c.title.ifBlank { c.id.take(6) }
            Text(
                if (c.kind == "edited-both") stringResource(R.string.sync_conflict_edited, title, stringResource(if (c.kept == "local") R.string.sync_kept_here else R.string.sync_kept_other))
                else stringResource(R.string.sync_conflict_deleted, title),
                style = MaterialTheme.typography.bodySmall,
            )
        }
    }
    SectionTitle(stringResource(R.string.sync_kept_title))
    TextButton(onClick = { kept = !kept }) { Text(stringResource(if (kept) R.string.hide else R.string.show)) }
    if (kept) {
        Text(stringResource(R.string.sync_kept_intro), style = MaterialTheme.typography.bodySmall)
        val withKept = ctl.entries.filter { keptVersions(it).isNotEmpty() }
        if (withKept.isEmpty()) Text(stringResource(R.string.sync_kept_none), style = MaterialTheme.typography.bodySmall)
        TextButton(onClick = { values = !values }) { Text(stringResource(if (values) R.string.hide else R.string.show) + " " + stringResource(R.string.sync_kept_title).lowercase()) }
        for (e in withKept) {
            Text(e.title.ifBlank { e.id.take(6) }, style = MaterialTheme.typography.titleSmall)
            for (v in keptVersions(e)) {
                val at = (v["at"] as? kotlinx.serialization.json.JsonPrimitive)?.content?.toLongOrNull() ?: 0L
                Text(stringResource(R.string.sync_version_at, if (at > 0) fmt.format(java.util.Date(at)) else "-"), style = MaterialTheme.typography.bodySmall)
                val data = v["data"] as? JsonObject ?: continue
                for ((k, x) in data) {
                    if (k in setOf("history", "updated", "created", "conflicts")) continue
                    if (e.data[k] == x) continue
                    val text = (x as? kotlinx.serialization.json.JsonPrimitive)?.takeIf { it.isString }?.content ?: x.toString()
                    val secret = Regex("pass|key|pin|cvv|number|secret|totp|value", RegexOption.IGNORE_CASE).containsMatchIn(k)
                    Text("  $k: " + if (values || !secret) text else "••••••••", style = MaterialTheme.typography.bodySmall)
                }
            }
        }
    }
}

private fun keptVersions(e: Entry): List<JsonObject> = (e.data["conflicts"] as? kotlinx.serialization.json.JsonArray)?.mapNotNull { it as? JsonObject } ?: emptyList()

/* ───────────────────────── import / export ───────────────────────── */

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ImportScreen(onBack: () -> Unit) {
    val ctx = LocalContext.current
    val ctl = ctx.pevv.vault
    val op = rememberOp()
    val run = op.runner()
    var preview by remember { mutableStateOf<ImportResult?>(null) }
    var needPw by remember { mutableStateOf<String?>(null) }
    var pw by remember { mutableStateOf("") }
    var exportPw by remember { mutableStateOf("") }
    var exportText by remember { mutableStateOf<String?>(null) }
    var envName by remember { mutableStateOf("dev") }
    val pick = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) run {
            val t = readText(ctx, uri)
            if (VaultEngine.peekExport(t) != 0) { needPw = t; return@run }
            preview = Import.importManagerExport(t)
        }
    }
    val pickEnv = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) run {
            val vars = Import.parseDotenv(readText(ctx, uri))
            preview = Import.envItems(vars, envName)
        }
    }
    val save = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/json")) { uri ->
        val t = exportText
        if (uri != null && t != null) run { saveText(ctx, uri, t); exportText = null; op.message = ctx.getString(R.string.saved) }
    }
    Scaffold(topBar = { BackBar(stringResource(R.string.sec_import_export), onBack) }) { pad ->
        Page(Modifier.padding(pad)) {
            SectionTitle(stringResource(R.string.import_items))
            Text(stringResource(R.string.import_body))
            SecondaryButton(stringResource(R.string.import_pick), { pick.launch(arrayOf("*/*")) })
            OutlinedTextField(envName, { envName = it }, label = { Text(stringResource(R.string.env_target)) }, singleLine = true, modifier = Modifier.fillMaxWidth())
            SecondaryButton(stringResource(R.string.import_dotenv), { pickEnv.launch(arrayOf("*/*")) })
            preview?.let { p ->
                InfoCard(stringResource(R.string.import_preview, p.entries.size, p.skipped, p.source))
                PrimaryButton(stringResource(R.string.import_confirm), { run { val n = ctl.saveEntries(p.entries); preview = null; op.message = ctx.getString(R.string.imported_n, n) } }, enabled = p.entries.isNotEmpty())
                TextButton(onClick = { preview = null }) { Text(stringResource(R.string.cancel)) }
            }
            needPw?.let { t ->
                Text(stringResource(R.string.export_password_prompt))
                SecretField(pw, { pw = it }, stringResource(R.string.export_password))
                PrimaryButton(stringResource(R.string.open), {
                    run {
                        when (val o = VaultEngine.openExport(t, pw)) {
                            is VaultEngine.Opened.Items -> preview = ImportResult("export", o.entries, 0)
                            is VaultEngine.Opened.Vault -> throw IllegalArgumentException(ctx.getString(R.string.err_full_vault_export))
                        }
                        needPw = null; pw = ""
                    }
                }, enabled = pw.isNotEmpty())
            }
            HorizontalDivider()
            SectionTitle(stringResource(R.string.export_vault))
            Text(stringResource(R.string.export_body))
            SecretField(exportPw, { exportPw = it }, stringResource(R.string.export_password))
            SecondaryButton(stringResource(R.string.export_save), {
                run { exportText = ctl.exportPortable(exportPw); save.launch("pevv-export.json"); exportPw = "" }
            }, enabled = exportPw.length >= 8 && !op.busy)
            if (op.busy) Busy(stringResource(R.string.working))
            op.message?.let { Done(it) }
            op.error?.let { Text(errorText(it), color = MaterialTheme.colorScheme.error) }
        }
    }
}
