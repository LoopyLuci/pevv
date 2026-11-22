package dev.pevv.app.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Star
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
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
import dev.pevv.app.core.Entry
import dev.pevv.app.core.EntryKinds
import dev.pevv.app.core.FieldSpec
import dev.pevv.app.core.ENTRY_TYPES
import dev.pevv.app.core.GenOpts
import dev.pevv.app.core.Totp
import dev.pevv.app.core.jbool
import dev.pevv.app.core.jstr
import dev.pevv.app.core.jstrs
import dev.pevv.app.core.with
import dev.pevv.app.pevv
import kotlinx.coroutines.delay
import kotlinx.serialization.json.JsonElement

@Composable
fun typeLabel(t: String): String = stringResource(
    when (t) {
        "login" -> R.string.type_login; "env" -> R.string.type_env; "note" -> R.string.type_note; "apikey" -> R.string.type_apikey
        "card" -> R.string.type_card; "ssh" -> R.string.type_ssh; "identity" -> R.string.type_identity; "passkey" -> R.string.type_passkey
        else -> R.string.type_note
    },
)

@Composable
fun fieldLabel(f: FieldSpec): String = stringResource(
    when (f.labelRes) {
        "site" -> R.string.f_site; "username" -> R.string.f_username; "password" -> R.string.f_password; "totp" -> R.string.f_totp
        "env_name" -> R.string.f_env_name; "env_value" -> R.string.f_env_value; "env_environment" -> R.string.f_env_environment
        "service" -> R.string.f_service; "api_key" -> R.string.f_api_key; "cardholder" -> R.string.f_cardholder; "card_number" -> R.string.f_card_number
        "expiry" -> R.string.f_expiry; "cvv" -> R.string.f_cvv; "pin" -> R.string.f_pin; "ssh_private" -> R.string.f_ssh_private
        "ssh_public" -> R.string.f_ssh_public; "passphrase" -> R.string.f_passphrase; "full_name" -> R.string.f_full_name
        "email" -> R.string.f_email; "phone" -> R.string.f_phone; "address" -> R.string.f_address; "rp_id" -> R.string.f_rp_id
        "rp_name" -> R.string.f_rp_name; "display_name" -> R.string.f_display_name; "credential_id" -> R.string.f_credential_id
        else -> R.string.f_notes
    },
)

/* ───────────────────────── list ───────────────────────── */

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ItemListScreen(onOpen: (String) -> Unit, onNew: (String) -> Unit, onSettings: () -> Unit, onGenerator: () -> Unit) {
    val ctl = LocalContext.current.pevv.vault
    var query by remember { mutableStateOf("") }
    var filter by remember { mutableStateOf<String?>(null) }
    var favOnly by remember { mutableStateOf(false) }
    var menu by remember { mutableStateOf(false) }
    val shown = ctl.entries.filter { it.isListable && (filter == null || it.type == filter) && (!favOnly || it.favorite) && EntryKinds.matchesQuery(it, query) }
        .sortedWith(compareByDescending<Entry> { it.favorite }.thenBy { it.title.lowercase() })
    val reuse = remember(ctl.entries) { EntryKinds.reuseGroups(ctl.entries) }

    Scaffold(
        topBar = {
            TopAppBar(title = { Text(stringResource(R.string.app_name)) }, actions = {
                TextButton(onClick = onGenerator) { Text(stringResource(R.string.generator)) }
                IconButton(onClick = onSettings) { Icon(Icons.Filled.Settings, contentDescription = stringResource(R.string.settings)) }
                TextButton(onClick = { ctl.lock() }) { Text(stringResource(R.string.lock_now)) }
            })
        },
        floatingActionButton = {
            Box {
                FloatingActionButton(onClick = { menu = true }, modifier = Modifier.semantics { contentDescription = "new" }) { Icon(Icons.Filled.Add, contentDescription = stringResource(R.string.new_item)) }
                DropdownMenu(expanded = menu, onDismissRequest = { menu = false }) {
                    for (t in ENTRY_TYPES.filter { it != "passkey" }) DropdownMenuItem(text = { Text(typeLabel(t)) }, onClick = { menu = false; onNew(t) })
                }
            }
        },
    ) { pad ->
        Column(Modifier.padding(pad).fillMaxSize()) {
            OutlinedTextField(query, { query = it; ctl.touch() }, label = { Text(stringResource(R.string.search)) }, singleLine = true, modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp))
            LazyRow(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp)) {
                item { FilterChip(selected = filter == null && !favOnly, onClick = { filter = null; favOnly = false }, label = { Text(stringResource(R.string.all)) }) }
                item { FilterChip(selected = favOnly, onClick = { favOnly = !favOnly }, label = { Text(stringResource(R.string.favorites)) }) }
                items(ENTRY_TYPES.filter { it != "passkey" }) { t -> FilterChip(selected = filter == t, onClick = { filter = if (filter == t) null else t }, label = { Text(typeLabel(t)) }) }
            }
            if (ctl.warnings.isNotEmpty()) InfoCard(stringResource(R.string.warnings_found, ctl.warnings.size), warn = true)
            if (shown.isEmpty()) {
                Box(Modifier.fillMaxSize().padding(24.dp), contentAlignment = Alignment.Center) {
                    Text(stringResource(if (ctl.entries.none { it.isListable }) R.string.no_items else R.string.no_matches), style = MaterialTheme.typography.bodyLarge)
                }
            } else LazyColumn(Modifier.fillMaxSize()) {
                items(shown, key = { it.id }) { e ->
                    ListItem(
                        headlineContent = { Text(e.title.ifEmpty { stringResource(R.string.untitled) }) },
                        supportingContent = { Text(EntryKinds.subtitle(e), maxLines = 1) },
                        overlineContent = { Text(typeLabel(e.type) + (if (reuse.containsKey(e.id)) " · " + stringResource(R.string.reused) else "")) },
                        trailingContent = { if (e.favorite) Icon(Icons.Filled.Star, contentDescription = stringResource(R.string.favorite)) },
                        modifier = Modifier.clickable { onOpen(e.id) },
                    )
                    HorizontalDivider()
                }
            }
        }
    }
}

/* ───────────────────────── detail ───────────────────────── */

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ItemDetailScreen(id: String, onBack: () -> Unit, onEdit: () -> Unit) {
    val ctx = LocalContext.current
    val ctl = ctx.pevv.vault
    val e = ctl.entries.firstOrNull { it.id == id }
    var confirmDelete by remember { mutableStateOf(false) }
    val op = rememberOp()
    val run = op.runner()
    if (e == null) { LaunchedEffect(Unit) { onBack() }; return }
    Scaffold(topBar = {
        TopAppBar(
            title = { Text(e.title.ifEmpty { stringResource(R.string.untitled) }, maxLines = 1) },
            navigationIcon = { IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = stringResource(R.string.back)) } },
            actions = {
                if (e.type != "passkey") IconButton(onClick = onEdit) { Icon(Icons.Filled.Edit, contentDescription = stringResource(R.string.edit)) }
                IconButton(onClick = { confirmDelete = true }) { Icon(Icons.Filled.Delete, contentDescription = stringResource(R.string.delete)) }
            },
        )
    }) { pad ->
        Page(Modifier.padding(pad)) {
            Text(typeLabel(e.type), style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.primary)
            for (f in EntryKinds.fields[e.type] ?: emptyList()) {
                val v = e.s(f.key) ?: continue
                if (v.isEmpty()) continue
                FieldRow(fieldLabel(f), v, f.secret)
            }
            if (e.type == "login" && !e.s("totp").isNullOrEmpty()) TotpRow(e.s("totp")!!)
            if (!e.notes.isNullOrEmpty() && e.type != "passkey") FieldRow(stringResource(R.string.f_notes), e.notes!!, false)
            e.folder?.takeIf { it.isNotEmpty() }?.let { FieldRow(stringResource(R.string.folder), it, false) }
            if (e.tags.isNotEmpty()) FieldRow(stringResource(R.string.tags), e.tags.joinToString(", "), false)
            if (e.type == "passkey") InfoCard(stringResource(R.string.passkey_item_note))
            if (e.history.isNotEmpty()) {
                SectionTitle(stringResource(R.string.history))
                for (h in e.history.take(10)) {
                    val field = (h["field"] as? kotlinx.serialization.json.JsonPrimitive)?.content ?: ""
                    val value = (h["value"] as? kotlinx.serialization.json.JsonPrimitive)?.content ?: ""
                    FieldRow(field, value, true)
                }
            }
            op.error?.let { Text(errorText(it), color = MaterialTheme.colorScheme.error) }
        }
    }
    if (confirmDelete) ConfirmDialog(stringResource(R.string.delete_title), stringResource(R.string.delete_body), stringResource(R.string.delete), {
        confirmDelete = false
        run { ctl.deleteEntry(id); onBack() }
    }, { confirmDelete = false }, danger = true)
}

@Composable
fun FieldRow(label: String, value: String, secret: Boolean) {
    val ctx = LocalContext.current
    val ctl = ctx.pevv.vault
    var shown by remember { mutableStateOf(false) }
    var ask by remember { mutableStateOf(false) }
    var pw by remember { mutableStateOf("") }
    val op = rememberOp()
    val run = op.runner()
    val shownText = if (!secret || shown) value else "•".repeat(minOf(value.length, 12).coerceAtLeast(8))
    Column(Modifier.fillMaxWidth()) {
        Text(label, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(shownText, Modifier.weight(1f).semantics { if (secret && !shown) contentDescription = "$label, hidden" }, style = MaterialTheme.typography.bodyLarge)
            if (secret) TextButton(onClick = { if (shown) shown = false else if (ctl.canReveal()) shown = true else ask = true }) { Text(stringResource(if (shown) R.string.hide else R.string.show)) }
            TextButton(onClick = { copySecret(ctx, label, value) }, modifier = Modifier.semantics { contentDescription = "${ctx.getString(R.string.copy)} $label" }) { Text(stringResource(R.string.copy)) }
        }
    }
    if (ask) androidx.compose.material3.AlertDialog(
        onDismissRequest = { ask = false }, title = { Text(stringResource(R.string.reauth_title)) },
        text = { Column { Text(stringResource(R.string.reauth_body)); SecretField(pw, { pw = it }, stringResource(R.string.master_password)); op.error?.let { Text(errorText(it), color = MaterialTheme.colorScheme.error) } } },
        confirmButton = { TextButton(onClick = { run { if (ctl.reauth(pw)) { shown = true; ask = false; pw = "" } else throw dev.pevv.app.core.DecryptError() } }) { Text(stringResource(R.string.show)) } },
        dismissButton = { TextButton(onClick = { ask = false; pw = "" }) { Text(stringResource(R.string.cancel)) } },
    )
}

@Composable
fun TotpRow(source: String) {
    val ctx = LocalContext.current
    var now by remember { mutableStateOf(System.currentTimeMillis()) }
    LaunchedEffect(source) { while (true) { now = System.currentTimeMillis(); delay(1000) } }
    val cfg = remember(source) { try { Totp.parse(source) } catch (_: Exception) { null } }
    if (cfg == null) { Text(stringResource(R.string.totp_invalid), color = MaterialTheme.colorScheme.error); return }
    val code = Totp.totpAt(cfg, now)
    Column(Modifier.fillMaxWidth()) {
        Text(stringResource(R.string.f_totp), style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(code.chunked(3).joinToString(" "), Modifier.weight(1f).semantics { contentDescription = code.toCharArray().joinToString(" ") }, style = MaterialTheme.typography.headlineSmall)
            Text(stringResource(R.string.seconds_left, Totp.secondsLeft(cfg, now)), style = MaterialTheme.typography.bodySmall)
            TextButton(onClick = { copySecret(ctx, "code", code) }) { Text(stringResource(R.string.copy)) }
        }
    }
}

/* ───────────────────────── edit ───────────────────────── */

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ItemEditScreen(id: String?, type: String, onDone: (String?) -> Unit, onBack: () -> Unit) {
    val ctx = LocalContext.current
    val ctl = ctx.pevv.vault
    val existing = id?.let { i -> ctl.entries.firstOrNull { it.id == i } }
    val kind = existing?.type ?: type
    val specs = EntryKinds.fields[kind] ?: emptyList()
    val values = remember { mutableStateOf(specs.associate { it.key to (existing?.s(it.key) ?: "") }) }
    var title by remember { mutableStateOf(existing?.title ?: "") }
    var notes by remember { mutableStateOf(existing?.notes ?: "") }
    var folder by remember { mutableStateOf(existing?.folder ?: "") }
    var tags by remember { mutableStateOf(existing?.tags?.joinToString(", ") ?: "") }
    var fav by remember { mutableStateOf(existing?.favorite ?: false) }
    var gen by remember { mutableStateOf<String?>(null) }
    val op = rememberOp()
    val run = op.runner()

    Scaffold(topBar = {
        TopAppBar(
            title = { Text(typeLabel(kind)) },
            navigationIcon = { IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = stringResource(R.string.back)) } },
            actions = {
                TextButton(enabled = title.isNotBlank() && !op.busy, onClick = {
                    run {
                        val changes = LinkedHashMap<String, JsonElement?>()
                        changes["title"] = jstr(title.trim())
                        for (s in specs) {
                            val v = values.value[s.key] ?: ""
                            changes[s.key] = if (v.isEmpty()) null else jstr(v)
                        }
                        changes["notes"] = if (notes.isEmpty()) null else jstr(notes)
                        changes["folder"] = if (folder.isBlank()) null else jstr(folder.trim().take(40))
                        changes["tags"] = jstrs(tags.split(',').map { it.trim() }.filter { it.isNotEmpty() }.distinct().take(20))
                        changes["favorite"] = jbool(fav)
                        if (kind == "login" && !(changes["totp"] as? kotlinx.serialization.json.JsonPrimitive)?.content.isNullOrEmpty()) {
                            // accept an otpauth:// link or a bare secret, but never store something that cannot make a code
                            Totp.parse((changes["totp"] as kotlinx.serialization.json.JsonPrimitive).content)
                        }
                        val saved = if (existing != null) ctl.editEntry(existing, changes) else ctl.saveEntry(null, EntryKinds.newData(kind).with(changes))
                        onDone(saved.id)
                    }
                }) { Text(stringResource(R.string.save)) }
            },
        )
    }) { pad ->
        Page(Modifier.padding(pad)) {
            OutlinedTextField(title, { title = it }, label = { Text(stringResource(R.string.title)) }, singleLine = true, modifier = Modifier.fillMaxWidth())
            for (s in specs) {
                val label = fieldLabel(s)
                val v = values.value[s.key] ?: ""
                val set = { x: String -> values.value = values.value + (s.key to x) }
                if (s.secret) {
                    SecretField(v, set, label, singleLine = !s.multiline)
                    if (s.key == "password" || s.key == "key" || s.key == "value") TextButton(onClick = { gen = s.key }) { Text(stringResource(R.string.generate)) }
                } else OutlinedTextField(v, set, label = { Text(label) }, singleLine = !s.multiline, minLines = if (s.multiline) 3 else 1, modifier = Modifier.fillMaxWidth())
            }
            OutlinedTextField(notes, { notes = it }, label = { Text(stringResource(R.string.f_notes)) }, minLines = 3, modifier = Modifier.fillMaxWidth())
            OutlinedTextField(folder, { folder = it }, label = { Text(stringResource(R.string.folder)) }, singleLine = true, modifier = Modifier.fillMaxWidth())
            OutlinedTextField(tags, { tags = it }, label = { Text(stringResource(R.string.tags_hint)) }, singleLine = true, modifier = Modifier.fillMaxWidth())
            Row(verticalAlignment = Alignment.CenterVertically) { Switch(fav, { fav = it }); Text(stringResource(R.string.favorite), Modifier.padding(start = 8.dp)) }
            if (op.busy) Busy()
            op.error?.let { Text(errorText(it), color = MaterialTheme.colorScheme.error) }
            Spacer(Modifier.height(48.dp))
        }
    }
    gen?.let { key ->
        androidx.compose.material3.AlertDialog(
            onDismissRequest = { gen = null }, title = { Text(stringResource(R.string.generator)) },
            text = { GeneratorPanel(onUse = { pw -> values.value = values.value + (key to pw); gen = null }) },
            confirmButton = {}, dismissButton = { TextButton(onClick = { gen = null }) { Text(stringResource(R.string.cancel)) } },
        )
    }
    @Suppress("UNUSED_EXPRESSION") GenOpts()
}
