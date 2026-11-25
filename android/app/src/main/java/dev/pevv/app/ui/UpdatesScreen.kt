package dev.pevv.app.ui

import android.Manifest
import android.os.Build
import android.text.format.DateUtils
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
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
import dev.pevv.app.BuildConfig
import dev.pevv.app.R
import dev.pevv.app.pevv
import dev.pevv.app.update.CheckResult
import dev.pevv.app.update.ReleaseInfo
import dev.pevv.app.update.UpdateException
import dev.pevv.app.update.UpdateMode
import dev.pevv.app.update.UpdateScheduler
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

private fun errorKey(code: String): Int = when {
    code.startsWith("checksum") -> R.string.upd_err_checksum
    code == "signature" -> R.string.upd_err_signature
    code == "version" -> R.string.upd_err_version
    code == "package" -> R.string.upd_err_package
    code == "https" -> R.string.upd_err_https
    code == "release" -> R.string.upd_err_release
    code.startsWith("install") -> R.string.upd_err_install
    else -> R.string.upd_err_network
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun UpdatesScreen(onBack: () -> Unit) {
    val ctx = LocalContext.current
    val app = ctx.pevv
    val upd = app.updates
    val prefs = upd.prefs
    val scope = rememberCoroutineScope()
    var mode by remember { mutableStateOf(prefs.mode) }
    var pre by remember { mutableStateOf(prefs.includePreReleases) }
    var unmetered by remember { mutableStateOf(prefs.unmeteredOnly) }
    var lastCheck by remember { mutableStateOf(prefs.lastCheck) }
    var found by remember { mutableStateOf<ReleaseInfo?>(null) }
    var ready by remember { mutableStateOf(prefs.ready) }
    var busy by remember { mutableStateOf(false) }
    var msg by remember { mutableStateOf<Int?>(null) }
    var err by remember { mutableStateOf(prefs.lastError) }
    var canInstall by remember { mutableStateOf(upd.canRequestInstalls()) }
    val notifPerm = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { }

    fun ensureNotifications() {
        if (Build.VERSION.SDK_INT >= 33 && !upd.canNotify()) notifPerm.launch(Manifest.permission.POST_NOTIFICATIONS)
    }

    fun check() {
        busy = true; msg = null
        scope.launch {
            val r = upd.check()
            lastCheck = prefs.lastCheck
            when (r) {
                is CheckResult.Available -> { found = r.release; msg = R.string.upd_available }
                CheckResult.UpToDate -> { found = null; msg = R.string.upd_up_to_date }
                is CheckResult.Failed -> { found = null; err = r.reason; msg = null }
            }
            if (r !is CheckResult.Failed) err = ""
            busy = false
        }
    }

    fun downloadAndInstall(rel: ReleaseInfo) {
        busy = true; msg = R.string.upd_downloading; err = ""
        scope.launch {
            try {
                ready = upd.download(rel)
                msg = R.string.upd_ready
                canInstall = upd.canRequestInstalls()
                if (canInstall) withContext(Dispatchers.IO) { upd.installReady(userInitiated = true) }.let { if (!it) msg = null }
                else msg = R.string.upd_need_unknown_sources
            } catch (e: UpdateException) {
                err = e.code; msg = null; ready = null
            }
            busy = false
        }
    }

    Scaffold(topBar = { BackBar(stringResource(R.string.sec_updates), onBack) }) { pad ->
        Page(Modifier.padding(pad)) {
            Text(stringResource(R.string.upd_current, BuildConfig.VERSION_NAME))
            Text(
                if (lastCheck == 0L) stringResource(R.string.upd_never_checked)
                else stringResource(R.string.upd_last_checked, DateUtils.formatDateTime(ctx, lastCheck, DateUtils.FORMAT_SHOW_DATE or DateUtils.FORMAT_SHOW_TIME or DateUtils.FORMAT_ABBREV_MONTH)),
                style = MaterialTheme.typography.bodySmall,
            )
            PrimaryButton(stringResource(R.string.upd_check_now), { check() }, enabled = !busy)
            msg?.let { Text(stringResource(it)) }
            if (err.isNotEmpty()) Text(stringResource(errorKey(err)), color = MaterialTheme.colorScheme.error)

            val rel = found
            if (rel != null) {
                Text(stringResource(R.string.upd_new_version, rel.tag), style = MaterialTheme.typography.titleMedium)
                PrimaryButton(stringResource(R.string.upd_download_install), { downloadAndInstall(rel) }, enabled = !busy)
            } else if (ready != null) {
                Text(stringResource(R.string.upd_ready_tag, ready!!.tag))
                PrimaryButton(stringResource(R.string.upd_install_now), {
                    scope.launch { withContext(Dispatchers.IO) { upd.installReady(userInitiated = true) } }
                    canInstall = upd.canRequestInstalls()
                }, enabled = !busy)
            }
            if (!canInstall) {
                Text(stringResource(R.string.upd_need_unknown_sources), color = MaterialTheme.colorScheme.error)
                SecondaryButton(stringResource(R.string.upd_open_unknown_sources), { ctx.startActivity(upd.unknownSourcesIntent()) })
            }

            SectionTitle(stringResource(R.string.upd_mode))
            for ((m, label, help) in listOf(
                Triple(UpdateMode.MANUAL, R.string.upd_mode_manual, R.string.upd_mode_manual_help),
                Triple(UpdateMode.AUTO_DOWNLOAD, R.string.upd_mode_download, R.string.upd_mode_download_help),
                Triple(UpdateMode.AUTO_INSTALL, R.string.upd_mode_install, R.string.upd_mode_install_help),
            )) {
                FilterChip(
                    selected = mode == m,
                    onClick = {
                        mode = m; prefs.mode = m
                        if (m != UpdateMode.MANUAL) ensureNotifications()
                        UpdateScheduler.schedulePeriodic(ctx)
                    },
                    label = { Text(stringResource(label)) },
                )
                Text(stringResource(help), style = MaterialTheme.typography.bodySmall)
            }
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(stringResource(R.string.upd_unmetered), Modifier.weight(1f))
                Switch(unmetered, { unmetered = it; prefs.unmeteredOnly = it })
            }
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(stringResource(R.string.upd_prerelease), Modifier.weight(1f))
                Switch(pre, { pre = it; prefs.includePreReleases = it })
            }
            Text(stringResource(if (upd.silentPossible()) R.string.upd_silent_yes else R.string.upd_silent_no), style = MaterialTheme.typography.bodySmall)
            if (!upd.canNotify()) Text(stringResource(R.string.upd_notif_off), style = MaterialTheme.typography.bodySmall)
        }
    }
}
