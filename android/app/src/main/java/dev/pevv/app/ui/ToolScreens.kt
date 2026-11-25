package dev.pevv.app.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Slider
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import dev.pevv.app.R
import dev.pevv.app.core.GenOpts
import dev.pevv.app.core.Generator
import dev.pevv.app.core.Json
import dev.pevv.app.core.PhraseOpts
import dev.pevv.app.core.Transfer
import dev.pevv.app.pevv
import dev.pevv.app.sync.SyncConfig
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

@Composable
fun GeneratorPanel(onUse: ((String) -> Unit)? = null) {
    val ctx = LocalContext.current
    var phrase by remember { mutableStateOf(false) }
    var opts by remember { mutableStateOf(GenOpts()) }
    var popts by remember { mutableStateOf(PhraseOpts()) }
    val words = remember { ctx.assets.open("eff_short_wordlist.txt").bufferedReader().readLines().filter { it.isNotBlank() } }
    var out by remember { mutableStateOf("") }
    fun regen() { out = if (phrase) Generator.generatePassphrase(popts, words) else Generator.generatePassword(opts) }
    LaunchedEffect(phrase, opts, popts) { regen() }
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Switch(phrase, { phrase = it })
            Text(stringResource(R.string.passphrase_mode), Modifier.padding(start = 8.dp))
        }
        Text(out, style = MaterialTheme.typography.titleMedium, modifier = Modifier.fillMaxWidth().semantics { contentDescription = ctx.getString(R.string.generated_desc, out.length) })
        val bits = if (phrase) Generator.phraseEntropyBits(popts, words.size) else Generator.entropyBits(opts)
        Text(stringResource(R.string.strength_bits, bits), style = MaterialTheme.typography.bodySmall)
        if (!phrase) {
            Text(stringResource(R.string.length_n, opts.length))
            Slider(opts.length.toFloat(), { opts = opts.copy(length = it.toInt()) }, valueRange = 8f..64f)
            ToggleRow(stringResource(R.string.lowercase), opts.lower) { opts = opts.copy(lower = it) }
            ToggleRow(stringResource(R.string.uppercase), opts.upper) { opts = opts.copy(upper = it) }
            ToggleRow(stringResource(R.string.digits), opts.digits) { opts = opts.copy(digits = it) }
            ToggleRow(stringResource(R.string.symbols), opts.symbols) { opts = opts.copy(symbols = it) }
            ToggleRow(stringResource(R.string.avoid_ambiguous), opts.avoidAmbiguous) { opts = opts.copy(avoidAmbiguous = it) }
        } else {
            Text(stringResource(R.string.words_n, popts.words))
            Slider(popts.words.toFloat(), { popts = popts.copy(words = it.toInt()) }, valueRange = 4f..12f)
            ToggleRow(stringResource(R.string.capitalize), popts.capitalize) { popts = popts.copy(capitalize = it) }
            ToggleRow(stringResource(R.string.add_number), popts.number) { popts = popts.copy(number = it) }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            TextButton(onClick = { regen() }) { Text(stringResource(R.string.regenerate)) }
            TextButton(onClick = { copySecret(ctx, "password", out) }) { Text(stringResource(R.string.copy)) }
            if (onUse != null) TextButton(onClick = { onUse(out) }) { Text(stringResource(R.string.use)) }
        }
    }
}

@Composable
private fun ToggleRow(label: String, on: Boolean, set: (Boolean) -> Unit) {
    Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
        Text(label, Modifier.weight(1f))
        Switch(on, set)
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun GeneratorScreen(onBack: () -> Unit) {
    Scaffold(topBar = { BackBar(stringResource(R.string.generator), onBack) }) { pad -> Page(Modifier.padding(pad)) { GeneratorPanel() } }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun BackBar(title: String, onBack: () -> Unit) {
    TopAppBar(title = { Text(title) }, navigationIcon = { IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = stringResource(R.string.back)) } })
}

/* ───────────────────────── scan ───────────────────────── */

/** Scan a vault QR (offline codes or a live transfer code) and install the vault on this phone. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ScanScreen(onBack: () -> Unit) {
    val app = LocalContext.current.pevv
    val frames = remember { mutableListOf<String>() }
    var progress by remember { mutableStateOf<String?>(null) }
    val op = rememberOp()
    val run = op.runner()
    var confirm by remember { mutableStateOf<Transfer.ScanHit?>(null) }
    fun handle(hit: Transfer.ScanHit) = run {
        val r = installFromScan(app, hit, frames)
        progress = when {
            r.startsWith("progress:") -> r.removePrefix("progress:")
            r == "waiting" -> "waiting"
            else -> null
        }
    }
    Scaffold(topBar = { BackBar(stringResource(R.string.scan_vault), onBack) }) { pad ->
        Column(Modifier.padding(pad).fillMaxSize()) {
            QrCamera({ text ->
                val hit = Transfer.parseScan(text)
                if (hit != null && !op.busy) {
                    if (app.vault.file != null && confirm == null && frames.isEmpty() && progress == null) confirm = hit else handle(hit)
                }
            }, Modifier.fillMaxWidth().height(320.dp))
            Page {
                Text(stringResource(R.string.scan_body))
                if (!SyncConfig.configured) Text(stringResource(R.string.scan_offline_only), style = MaterialTheme.typography.bodySmall)
                progress?.let { Text(if (it == "waiting") stringResource(R.string.waiting_sender) else stringResource(R.string.frames_read, it)) }
                if (op.busy) Busy(stringResource(R.string.working))
                op.error?.let { Text(errorText(it), color = MaterialTheme.colorScheme.error) }
            }
        }
    }
    confirm?.let { hit ->
        ConfirmDialog(stringResource(R.string.replace_vault_title), stringResource(R.string.replace_vault_body), stringResource(R.string.replace), { confirm = null; handle(hit) }, { confirm = null }, danger = true)
    }
}

/* ───────────────────────── show ───────────────────────── */

/** Show this vault as a QR for another phone: a live code (needs sync config) or offline codes that cycle. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ShareVaultScreen(onBack: () -> Unit) {
    val app = LocalContext.current.pevv
    val file = app.vault.file
    var live by remember { mutableStateOf(SyncConfig.configured) }
    var index by remember { mutableStateOf(0) }
    var liveCode by remember { mutableStateOf<String?>(null) }
    val op = rememberOp()
    val offline = remember(file?.rev) { try { file?.let { Transfer.packVault(it) } } catch (_: Exception) { null } }
    DisposableEffect(live, file?.rev) {
        val token = Transfer.newTransferToken()
        var job: kotlinx.coroutines.Job? = null
        if (live && file != null) {
            job = app.scope.launch {
                try {
                             val h = Transfer.sealHandoff(file.toText())
                             app.relay.putTransfer(token, Json.encode(h.envelope))
                             liveCode = Transfer.shareUrl("H.${h.key}.$token", SyncConfig.publicUrl)
                } catch (_: kotlinx.coroutines.CancellationException) {
                } catch (_: Exception) {
                }
            }
        }
        onDispose { job?.cancel(); app.relay.dropTransfer(token); liveCode = null }
    }
    LaunchedEffect(offline, live) { while (!live && (offline?.size ?: 0) > 1) { delay(1500); index = (index + 1) % offline!!.size } }
    Scaffold(topBar = { BackBar(stringResource(R.string.show_vault_qr), onBack) }) { pad ->
        Page(Modifier.padding(pad)) {
            InfoCard(stringResource(R.string.qr_no_password))
            if (SyncConfig.configured) Row(verticalAlignment = Alignment.CenterVertically) {
                Switch(live, { live = it }); Text(stringResource(R.string.live_transfer), Modifier.padding(start = 8.dp))
            }
            if (live) {
                val code = liveCode
                if (code != null) {
                    QrImage(code, stringResource(R.string.qr_live_desc), 640)
                    Text(stringResource(R.string.qr_live_body))
                } else Busy(stringResource(R.string.working))
            } else if (offline != null) {
                QrImage(offline[index], stringResource(R.string.qr_offline_desc, index + 1, offline.size), 640)
                Text(stringResource(R.string.qr_offline_body, index + 1, offline.size))
            } else InfoCard(stringResource(R.string.err_qr_too_big), warn = true)
            op.error?.let { Text(errorText(it), color = MaterialTheme.colorScheme.error) }
        }
    }
}

