package dev.pevv.app.autofill

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.content.res.Configuration
import android.os.Bundle
import android.service.autofill.Dataset
import android.view.WindowManager
import android.view.autofill.AutofillId
import android.view.autofill.AutofillManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import dev.pevv.app.R
import dev.pevv.app.core.EntryKinds
import dev.pevv.app.core.jstr
import dev.pevv.app.pevv
import dev.pevv.app.store.VaultController.Status
import dev.pevv.app.ui.PevvTheme
import dev.pevv.app.ui.SecondFactorScreen
import dev.pevv.app.ui.SetPasswordScreen
import dev.pevv.app.ui.UnlockScreen
import kotlinx.coroutines.launch
import kotlinx.serialization.json.JsonElement
import java.util.Locale

/** Base for the small screens the system opens for autofill and passkeys: secure window, app language, no recents preview of secrets. */
abstract class SecureActivity : ComponentActivity() {
    override fun attachBaseContext(newBase: Context) {
        super.attachBaseContext(
            try {
                val lang = newBase.getSharedPreferences("pevv_prefs", MODE_PRIVATE).getString("lang", "") ?: ""
                if (lang.isEmpty()) newBase else newBase.createConfigurationContext(Configuration(newBase.resources.configuration).also { it.setLocale(Locale(lang)) })
            } catch (_: Exception) { newBase },
        )
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        super.onCreate(savedInstanceState)
    }

    override fun onStart() {
        super.onStart()
        pevv.vault.cancelBackgroundLock()
        pevv.vault.touch()
    }

    override fun onStop() {
        super.onStop()
        if (!isChangingConfigurations) pevv.vault.lockAfter(pevv.prefs.lockMinutes * 60_000L)
    }
}

/** Shows the right unlock screen for the vault state, and [content] once it is unlocked. */
@Composable
fun UnlockGate(content: @Composable () -> Unit) {
    val ctl = androidx.compose.ui.platform.LocalContext.current.pevv.vault
    Surface(Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
        when (ctl.status) {
            Status.UNLOCKED -> content()
            Status.SECOND_FACTOR -> SecondFactorScreen()
            Status.SET_PASSWORD -> SetPasswordScreen()
            else -> UnlockScreen(compact = true)
        }
    }
}

/**
 * Opened by the autofill framework when the user taps a suggestion. The vault must be unlocked first (password, biometrics, key...);
 * only then is the login's user name and password handed back to the form.
 */
class AutofillAuthActivity : SecureActivity() {
    @Suppress("DEPRECATION")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val i = intent
        val pick = i.getBooleanExtra("pick", false)
        val entryId = i.getStringExtra(FormResponses.X_ENTRY)
        val form = ParsedForm(
            i.getParcelableExtra<AutofillId>(FormResponses.X_USER_ID), i.getParcelableExtra<AutofillId>(FormResponses.X_PASS_ID),
            i.getStringExtra(FormResponses.X_PKG) ?: "", i.getStringExtra(FormResponses.X_WEB), i.getStringExtra(FormResponses.X_SCHEME), null, null,
        )
        setContent {
            PevvTheme {
                UnlockGate {
                    val ctl = pevv.vault
                    val scope = rememberCoroutineScope()
                    val matches = ctl.entries
                    if (!pick) {
                        val e = matches.firstOrNull { it.id == entryId }
                        LaunchedEffect(e) { if (e != null) done(FormResponses.filledDataset(this@AutofillAuthActivity, form, e)) else cancel() }
                    } else {
                        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                            Text(stringResource(R.string.af_pick_title), style = MaterialTheme.typography.titleLarge)
                            Text(stringResource(R.string.af_pick_body, form.pkg), style = MaterialTheme.typography.bodyMedium)
                            LazyColumn(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                                items(Matching.logins(matches), key = { it.id }) { e ->
                                    Column(Modifier.fillMaxWidth().clickable {
                                        scope.launch {
                                            // The user chose this login for this app: remember the link (sealed in the vault), then fill.
                                            ctl.linkApp(form.pkg, e.id)
                                            done(FormResponses.filledDataset(this@AutofillAuthActivity, form, e))
                                        }
                                    }.padding(vertical = 8.dp)) {
                                        Text(e.title.ifEmpty { e.site ?: "" }, style = MaterialTheme.typography.titleMedium)
                                        Text(e.username ?: "", style = MaterialTheme.typography.bodySmall)
                                    }
                                }
                            }
                            OutlinedButton(onClick = { cancel() }, Modifier.fillMaxWidth()) { Text(stringResource(R.string.cancel)) }
                        }
                    }
                }
            }
        }
    }

    private fun done(ds: Dataset) {
        setResult(Activity.RESULT_OK, Intent().putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, ds))
        finish()
    }

    private fun cancel() {
        setResult(Activity.RESULT_CANCELED)
        finish()
    }
}

/** Offered after the user submits a login form in another app: save it into the vault (after unlocking), or discard it. */
class AutofillSaveActivity : SecureActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val pending = PendingSave.take()
        if (pending == null) { finish(); return }
        setContent {
            PevvTheme {
                UnlockGate {
                    val scope = rememberCoroutineScope()
                    val label = pending.site.ifEmpty { pending.pkg }
                    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                        Text(stringResource(R.string.af_save_title), style = MaterialTheme.typography.titleLarge)
                        Text(stringResource(R.string.af_save_body, label, pending.username.ifEmpty { "-" }), style = MaterialTheme.typography.bodyMedium)
                        Button(onClick = {
                            scope.launch {
                                val d = EntryKinds.newData("login")
                                val m = LinkedHashMap<String, JsonElement?>()
                                m["title"] = jstr(label.removePrefix("https://"))
                                m["site"] = jstr(pending.site)
                                m["username"] = jstr(pending.username)
                                m["password"] = jstr(pending.password)
                                val e = pevv.vault.saveEntry(null, EntryKinds.applyEdit(d, m))
                                if (pending.site.isEmpty()) pevv.vault.linkApp(pending.pkg, e.id)
                                finish()
                            }
                        }, Modifier.fillMaxWidth()) { Text(stringResource(R.string.save)) }
                        OutlinedButton(onClick = { finish() }, Modifier.fillMaxWidth()) { Text(stringResource(R.string.af_not_now)) }
                    }
                }
            }
        }
    }
}
