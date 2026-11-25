package dev.pevv.app.ui

import android.app.Activity
import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.CenterAlignedTopAppBar
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.size
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.foundation.text.KeyboardOptions
import dev.pevv.app.R
import dev.pevv.app.core.Generator
import dev.pevv.app.core.Json
import dev.pevv.app.core.Transfer
import dev.pevv.app.core.VaultEngine
import dev.pevv.app.core.VaultFile
import dev.pevv.app.passkey.PasskeyAuth
import dev.pevv.app.pevv
import dev.pevv.app.security.BiometricVault
import dev.pevv.app.store.VaultController
import dev.pevv.app.sync.SyncConfig
import kotlinx.coroutines.launch

/** Runs one action at a time and keeps its busy flag and last error for the screen. */
class Op {
    var busy by mutableStateOf(false)
    var error by mutableStateOf<Throwable?>(null)
    var message by mutableStateOf<String?>(null)
}

@Composable
fun rememberOp(): Op = remember { Op() }

@Composable
fun Op.runner(): (suspend () -> Unit) -> Unit {
    val scope = rememberCoroutineScope()
    return { block ->
        if (!busy) {
            busy = true
            error = null
            scope.launch {
                try { block() } catch (e: kotlinx.coroutines.CancellationException) { throw e } catch (e: Throwable) { error = e } finally { busy = false }
            }
        }
    }
}

fun readText(ctx: android.content.Context, uri: Uri, max: Int = 4_000_000): String {
    ctx.contentResolver.openInputStream(uri)!!.use { s ->
        val bo = java.io.ByteArrayOutputStream()
        val buf = ByteArray(8192)
        while (bo.size() <= max) {
            val n = s.read(buf)
            if (n < 0) break
            bo.write(buf, 0, n)
        }
        val b = bo.toByteArray()
        require(b.size <= max) { "That file is too large." }
        return String(b, Charsets.UTF_8)
    }
}

/* ───────────────────────── onboarding ───────────────────────── */

private enum class Step { START, CREATE, SIGN_IN, EXPORT_PASSWORD }

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun OnboardingScreen(onScan: () -> Unit) {
    val ctx = LocalContext.current
    val app = ctx.pevv
    var step by remember { mutableStateOf(Step.START) }
    val op = rememberOp()
    val run = op.runner()
    var pendingExport by remember { mutableStateOf<String?>(null) }
    var exportPw by remember { mutableStateOf("") }
    val pick = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) run {
            val text = readText(ctx, uri)
            when {
                VaultEngine.peekExport(text) == 2 -> { pendingExport = text; step = Step.EXPORT_PASSWORD }
                VaultEngine.peekExport(text) == 1 -> throw IllegalArgumentException(ctx.getString(R.string.err_items_only))
                else -> app.vault.installVaultCopy(VaultFile.parse(text))
            }
        }
    }

    Scaffold(topBar = { CenterAlignedTopAppBar(title = { Text(stringResource(R.string.app_name)) }) }) { pad ->
        Page(Modifier.padding(pad)) {
            when (step) {
                Step.START -> {
                    Image(painterResource(R.drawable.pevv_logo), contentDescription = stringResource(R.string.logo_desc), modifier = Modifier.size(96.dp).align(Alignment.CenterHorizontally))
                    Text(stringResource(R.string.onboard_title), style = MaterialTheme.typography.headlineSmall)
                    Text(stringResource(R.string.onboard_body))
                    PrimaryButton(stringResource(R.string.create_vault), { step = Step.CREATE })
                    SecondaryButton(stringResource(R.string.import_qr), onScan)
                    SecondaryButton(stringResource(R.string.import_file), { pick.launch(arrayOf("application/json", "text/plain", "application/octet-stream", "*/*")) })
                    if (SyncConfig.configured) SecondaryButton(stringResource(R.string.sign_in_sync), { step = Step.SIGN_IN })
                    else Text(stringResource(R.string.sync_not_configured), style = MaterialTheme.typography.bodySmall)
                    if (op.busy) Busy()
                    op.error?.let { Text(errorText(it), color = MaterialTheme.colorScheme.error) }
                }
                Step.CREATE -> CreateVaultForm(onBack = { step = Step.START })
                Step.SIGN_IN -> SignInForm(onBack = { step = Step.START })
                Step.EXPORT_PASSWORD -> {
                    Text(stringResource(R.string.export_password_prompt))
                    SecretField(exportPw, { exportPw = it }, stringResource(R.string.export_password))
                    PrimaryButton(stringResource(R.string.open), {
                        run {
                            val opened = VaultEngine.openExport(pendingExport!!, exportPw) as VaultEngine.Opened.Vault
                            app.vault.installVaultCopy(opened.file)
                        }
                    }, enabled = exportPw.isNotEmpty() && !op.busy)
                    SecondaryButton(stringResource(R.string.back), { step = Step.START })
                    if (op.busy) Busy(stringResource(R.string.working))
                    op.error?.let { Text(errorText(it), color = MaterialTheme.colorScheme.error) }
                }
            }
        }
    }
}

@Composable
fun CreateVaultForm(onBack: () -> Unit) {
    val app = LocalContext.current.pevv
    var pw by remember { mutableStateOf("") }
    var pw2 by remember { mutableStateOf("") }
    var strong by remember { mutableStateOf(false) }
    val op = rememberOp()
    val run = op.runner()
    val bits = Generator.estimateBits(pw)
    Text(stringResource(R.string.create_vault), style = MaterialTheme.typography.titleLarge)
    InfoCard(stringResource(R.string.pw_warning), warn = true)
    SecretField(pw, { pw = it }, stringResource(R.string.master_password), supporting = if (pw.isNotEmpty()) stringResource(R.string.strength_bits, bits) else null)
    SecretField(pw2, { pw2 = it }, stringResource(R.string.confirm_password))
    Row(verticalAlignment = Alignment.CenterVertically) {
        androidx.compose.material3.Switch(checked = strong, onCheckedChange = { strong = it })
        Text(stringResource(R.string.strong_kdf), Modifier.padding(start = 8.dp))
    }
    val mismatch = pw2.isNotEmpty() && pw != pw2
    if (mismatch) Text(stringResource(R.string.passwords_differ), color = MaterialTheme.colorScheme.error)
    PrimaryButton(stringResource(R.string.create_vault), { run { app.vault.createVault(pw, strong) } }, enabled = pw.length >= 8 && pw == pw2 && !op.busy)
    if (pw.isNotEmpty() && pw.length < 8) Text(stringResource(R.string.pw_min_length), style = MaterialTheme.typography.bodySmall)
    SecondaryButton(stringResource(R.string.back), onBack)
    if (op.busy) Busy(stringResource(R.string.working))
    op.error?.let { Text(errorText(it), color = MaterialTheme.colorScheme.error) }
}

@Composable
fun SignInForm(onBack: () -> Unit) {
    val app = LocalContext.current.pevv
    var email by remember { mutableStateOf("") }
    var code by remember { mutableStateOf("") }
    var sent by remember { mutableStateOf(false) }
    val op = rememberOp()
    val run = op.runner()
    Text(stringResource(R.string.sign_in_sync), style = MaterialTheme.typography.titleLarge)
    Text(stringResource(R.string.sign_in_body))
    OutlinedTextField(email, { email = it }, label = { Text(stringResource(R.string.email)) }, singleLine = true, modifier = Modifier.fillMaxWidth(),
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Email))
    PrimaryButton(stringResource(if (sent) R.string.resend_code else R.string.send_code), { run { app.sync.sendCode(email); sent = true } }, enabled = email.contains("@") && !op.busy)
    if (sent) {
        Text(stringResource(R.string.code_sent))
        OutlinedTextField(code, { code = it }, label = { Text(stringResource(R.string.email_code)) }, singleLine = true, modifier = Modifier.fillMaxWidth(),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number))
        PrimaryButton(stringResource(R.string.sign_in), { run { app.sync.verifyCode(email, code); app.sync.pull() } }, enabled = code.length >= 6 && !op.busy)
    }
    if (app.sync.account != null) {
        Done(stringResource(R.string.signed_in_as, app.sync.account?.email ?: ""))
        Text(stringResource(R.string.waiting_cloud_vault))
    }
    SecondaryButton(stringResource(R.string.back), onBack)
    if (op.busy) Busy()
    op.error?.let { Text(errorText(it), color = MaterialTheme.colorScheme.error) }
}

/* ───────────────────────── unlock ───────────────────────── */

private enum class Mode { PASSWORD, RECOVERY_CODE, RECOVERY_KEY, KIT, KEY_FILE }

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun UnlockScreen(compact: Boolean = false) {
    val ctx = LocalContext.current
    val app = ctx.pevv
    val ctl = app.vault
    var mode by remember { mutableStateOf(Mode.PASSWORD) }
    var text by remember { mutableStateOf("") }
    var kitText by remember { mutableStateOf<String?>(null) }
    val op = rememberOp()
    val run = op.runner()
    val file = ctl.file
    val prfSlots = file?.slots?.filter { it.type == "prf" } ?: emptyList()
    val bioOn = app.prefs.biometricOn && app.bio.enrolled && app.bio.available
    val activity = ctx as? Activity

    fun bio() {
        val f = file ?: return
        app.bio.unlock(f.id, ctx.getString(R.string.bio_title), ctx.getString(R.string.bio_subtitle), ctx.getString(R.string.cancel)) { out ->
            when (out) {
                is BiometricVault.Outcome.Ok -> run { ctl.unlockWithKey(out.value!!) }
                is BiometricVault.Outcome.Invalidated -> { app.prefs.biometricOn = false; op.error = IllegalArgumentException(ctx.getString(R.string.bio_invalidated)) }
                is BiometricVault.Outcome.Failed -> op.error = IllegalArgumentException(ctx.getString(R.string.err_generic))
                BiometricVault.Outcome.Cancelled -> {}
            }
        }
    }
    LaunchedEffect(Unit) { if (bioOn && ctl.status == VaultController.Status.LOCKED) bio() }

    val pickKey = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) run {
            val t = readText(ctx, uri, 100_000)
            if (mode == Mode.KEY_FILE) ctl.unlockUsbKey(t) else kitText = t
        }
    }

    val content: @Composable () -> Unit = {
        Page(if (compact) Modifier else Modifier) {
            if (!compact) Image(painterResource(R.drawable.pevv_logo), contentDescription = stringResource(R.string.logo_desc), modifier = Modifier.size(72.dp).align(Alignment.CenterHorizontally))
            Text(stringResource(R.string.unlock_title), style = MaterialTheme.typography.headlineSmall)
            ctl.notice?.let { InfoCard(stringResource(if (it == "device-revoked") R.string.err_device_revoked else R.string.err_generic), warn = true) }
            when (mode) {
                Mode.PASSWORD -> {
                    SecretField(text, { text = it }, stringResource(R.string.master_password))
                    PrimaryButton(stringResource(R.string.unlock), { run { ctl.unlockPassword(text); text = "" } }, enabled = text.isNotEmpty() && !op.busy)
                    if (bioOn) SecondaryButton(stringResource(R.string.unlock_biometric), { bio() })
                    if (prfSlots.isNotEmpty() && activity != null) {
                        if (SyncConfig.rpId.isNotEmpty()) SecondaryButton(stringResource(R.string.unlock_passkey), {
                            run {
                                val r = PasskeyAuth.assertPrf(activity, SyncConfig.rpId, PasskeyAuth.prfCreds(file!!, prfSlots.map { it.credId }))
                                ctl.unlockPrf(r.credId, r.prfOutput ?: throw IllegalArgumentException(ctx.getString(R.string.err_prf_unsupported)))
                            }
                        }) else Text(stringResource(R.string.passkey_needs_rpid), style = MaterialTheme.typography.bodySmall)
                    }
                    TextButton(onClick = { mode = Mode.RECOVERY_CODE; text = "" }) { Text(stringResource(R.string.use_recovery)) }
                    if (file?.slots?.any { it.type == "usb-key" } == true) TextButton(onClick = { mode = Mode.KEY_FILE }) { Text(stringResource(R.string.use_key_file)) }
                }
                Mode.RECOVERY_CODE -> {
                    Text(stringResource(R.string.recovery_code_body))
                    OutlinedTextField(text, { text = it }, label = { Text(stringResource(R.string.recovery_code)) }, singleLine = true, modifier = Modifier.fillMaxWidth())
                    PrimaryButton(stringResource(R.string.unlock), { run { ctl.unlockRecoveryCode(text); text = "" } }, enabled = text.isNotBlank() && !op.busy)
                    TextButton(onClick = { mode = Mode.RECOVERY_KEY; text = "" }) { Text(stringResource(R.string.use_recovery_key)) }
                    TextButton(onClick = { mode = Mode.KIT; text = "" }) { Text(stringResource(R.string.use_recovery_kit)) }
                    TextButton(onClick = { mode = Mode.PASSWORD; text = "" }) { Text(stringResource(R.string.back)) }
                }
                Mode.RECOVERY_KEY -> {
                    OutlinedTextField(text, { text = it }, label = { Text(stringResource(R.string.recovery_key)) }, modifier = Modifier.fillMaxWidth())
                    PrimaryButton(stringResource(R.string.unlock), { run { ctl.unlockRecoveryKey(text); text = "" } }, enabled = text.isNotBlank() && !op.busy)
                    TextButton(onClick = { mode = Mode.RECOVERY_CODE; text = "" }) { Text(stringResource(R.string.back)) }
                }
                Mode.KIT -> {
                    Text(stringResource(R.string.kit_body))
                    SecondaryButton(stringResource(if (kitText == null) R.string.choose_kit_file else R.string.kit_file_chosen), { pickKey.launch(arrayOf("*/*")) })
                    SecretField(text, { text = it }, stringResource(R.string.kit_passphrase))
                    PrimaryButton(stringResource(R.string.unlock), { run { ctl.unlockRecoveryKit(kitText!!, text); text = "" } }, enabled = kitText != null && text.isNotEmpty() && !op.busy)
                    TextButton(onClick = { mode = Mode.RECOVERY_CODE; text = "" }) { Text(stringResource(R.string.back)) }
                }
                Mode.KEY_FILE -> {
                    Text(stringResource(R.string.key_file_body))
                    SecondaryButton(stringResource(R.string.choose_key_file), { pickKey.launch(arrayOf("*/*")) })
                    TextButton(onClick = { mode = Mode.PASSWORD }) { Text(stringResource(R.string.back)) }
                }
            }
            if (op.busy) Busy(stringResource(R.string.working))
            op.error?.let { Text(errorText(it), color = MaterialTheme.colorScheme.error, modifier = Modifier.semantics { contentDescription = "error" }) }
            if (!compact) {
                Text(stringResource(R.string.vault_on_device), style = MaterialTheme.typography.bodySmall)
            }
        }
    }
    if (compact) content() else Scaffold(topBar = { CenterAlignedTopAppBar(title = { Text(stringResource(R.string.app_name)) }) }) { pad -> Column(Modifier.padding(pad)) { content() } }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SecondFactorScreen() {
    val ctx = LocalContext.current
    val app = ctx.pevv
    val ctl = app.vault
    var code by remember { mutableStateOf("") }
    val op = rememberOp()
    val run = op.runner()
    val pick = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) run { ctl.verifySecondUsbKey(readText(ctx, uri, 100_000)) }
    }
    Scaffold(topBar = { TopAppBar(title = { Text(stringResource(R.string.second_factor)) }, actions = { TextButton(onClick = { ctl.lock() }) { Text(stringResource(R.string.cancel)) } }) }) { pad ->
        Page(Modifier.padding(pad)) {
            Text(stringResource(R.string.second_factor_body))
            if (ctl.pending.totp) {
                OutlinedTextField(code, { code = it.filter(Char::isDigit).take(8) }, label = { Text(stringResource(R.string.auth_code)) }, singleLine = true, modifier = Modifier.fillMaxWidth(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number))
                PrimaryButton(stringResource(R.string.verify), { run { ctl.verifySecondTotp(code); code = "" } }, enabled = code.length >= 6 && !op.busy)
            }
            if (ctl.pending.usbKey) SecondaryButton(stringResource(R.string.choose_key_file), { pick.launch(arrayOf("*/*")) })
            if (ctl.pending.passkey) {
                val activity = ctx as? Activity
                if (activity != null && SyncConfig.rpId.isNotEmpty()) SecondaryButton(stringResource(R.string.use_passkey), {
                    run {
                        val r = PasskeyAuth.assertGate(activity, SyncConfig.rpId, ctl.file!!)
                        ctl.passkeyGatePassed(r.credId, r.signCount)
                    }
                }) else InfoCard(stringResource(R.string.passkey_gate_unavailable), warn = true)
            }
            if (op.busy) Busy()
            op.error?.let { Text(errorText(it), color = MaterialTheme.colorScheme.error) }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SetPasswordScreen() {
    val ctl = LocalContext.current.pevv.vault
    var pw by remember { mutableStateOf("") }
    var pw2 by remember { mutableStateOf("") }
    val op = rememberOp()
    val run = op.runner()
    Scaffold(topBar = { TopAppBar(title = { Text(stringResource(R.string.set_new_password)) }) }) { pad ->
        Page(Modifier.padding(pad)) {
            InfoCard(stringResource(R.string.set_password_body))
            SecretField(pw, { pw = it }, stringResource(R.string.new_password), supporting = if (pw.isNotEmpty()) stringResource(R.string.strength_bits, Generator.estimateBits(pw)) else null)
            SecretField(pw2, { pw2 = it }, stringResource(R.string.confirm_password))
            PrimaryButton(stringResource(R.string.save), { run { ctl.setPasswordAfterRecovery(pw) } }, enabled = pw.length >= 8 && pw == pw2 && !op.busy)
            if (op.busy) Busy(stringResource(R.string.working))
            op.error?.let { Text(errorText(it), color = MaterialTheme.colorScheme.error) }
        }
    }
}

/** Shared by the QR scanner and the file importer: a decoded code or file text becomes a vault on this device. */
suspend fun installFromScan(app: dev.pevv.app.PevvApp, hit: Transfer.ScanHit, frames: MutableList<String>): String {
    return when (hit) {
        is Transfer.ScanHit.FrameHit -> {
            val got = Transfer.addFrame(frames, hit.frame) ?: throw dev.pevv.app.core.TransferError("qr-damaged")
            if (!got.complete) return "progress:${got.got}/${got.need}"
            app.vault.installVaultCopy(try { Transfer.unpackFrames(frames.toList()) } catch (e: Exception) { frames.clear(); throw e })
            "done"
        }
        is Transfer.ScanHit.HandoffHit -> {
            val xfer = hit.xfer ?: throw dev.pevv.app.sync.SyncError("qr-nosync")
            val pulled = app.relay.pullTransfer(xfer)
            val body = pulled.body ?: return "waiting"
            val env = Json.parseObject(body)
            val json = Transfer.openHandoff(env, hit.key)
            app.vault.installVaultCopy(VaultFile.parse(json))
            app.relay.dropTransfer(xfer)
            "done"
        }
    }
}

