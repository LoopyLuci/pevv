package dev.pevv.app.update

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInfo
import android.content.pm.PackageInstaller
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.provider.Settings
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import androidx.core.content.pm.PackageInfoCompat
import dev.pevv.app.BuildConfig
import dev.pevv.app.MainActivity
import dev.pevv.app.R
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import java.io.File
import java.io.IOException
import java.security.MessageDigest
import java.util.concurrent.TimeUnit

/** Outcome of asking GitHub for the newest release. */
sealed class CheckResult {
    data class Available(val release: ReleaseInfo) : CheckResult()
    data object UpToDate : CheckResult()
    data class Failed(val reason: String) : CheckResult()
}

/** Why an update did not go ahead; shown in Settings. `code` is a stable key. */
class UpdateException(val code: String, msg: String = code) : IOException(msg)

/**
 * Checks GitHub releases, downloads and verifies the APK and installs it. Nothing is installed unless the bytes match SHA256SUMS,
 * the package is ours with a higher versionCode, and its signing certificate equals the one this app runs with.
 */
class UpdateManager(ctx: Context, private val vaultInUse: () -> Boolean) {
    private val app = ctx.applicationContext
    val prefs = UpdatePrefs(app)
    private val dir = File(app.cacheDir, "updates")
    private val io = kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.SupervisorJob() + Dispatchers.IO)

    /** Set by MainActivity: whether the UI is on screen. Used by the deferral rule. */
    @Volatile var foreground = false

    @Volatile var latest: ReleaseInfo? = null; private set

    private val client: OkHttpClient by lazy {
        OkHttpClient.Builder()
            .connectTimeout(15, TimeUnit.SECONDS).readTimeout(60, TimeUnit.SECONDS)
            // HTTPS only, on every hop of a redirect chain too.
            .addNetworkInterceptor { chain ->
                if (!chain.request().url.isHttps) throw UpdateException("https", "Refusing a non-HTTPS request")
                chain.proceed(chain.request())
            }
            .build()
    }

    // ---- check -------------------------------------------------------------------------------------------------

    suspend fun check(): CheckResult = withContext(Dispatchers.IO) {
        try {
            val pre = prefs.includePreReleases
            val url = if (pre) "$API/releases?per_page=15" else "$API/releases/latest"
            val body = getText(url, 1_000_000)
            val rel = if (pre) ReleaseParser.parseList(body, true) else ReleaseParser.parseLatest(body)
            prefs.lastCheck = System.currentTimeMillis()
            prefs.lastError = ""
            if (rel == null) { latest = null; return@withContext CheckResult.Failed("release") }
            latest = rel
            if (UpdatePolicy.isNewer(Version.installed(BuildConfig.VERSION_NAME), rel.version)) CheckResult.Available(rel) else CheckResult.UpToDate
        } catch (e: Exception) {
            val code = (e as? UpdateException)?.code ?: "network"
            prefs.lastError = code
            CheckResult.Failed(code)
        }
    }

    private fun getText(url: String, max: Long): String {
        val req = Request.Builder().url(url).header("Accept", "application/vnd.github+json").header("User-Agent", "pevv-android").build()
        client.newCall(req).execute().use { r ->
            if (!r.isSuccessful) throw UpdateException("http-${r.code}")
            val src = r.body?.source() ?: throw UpdateException("empty")
            val buf = okio.Buffer()
            while (buf.size <= max) if (src.read(buf, 8192) < 0) break
            if (buf.size > max) throw UpdateException("too-large")
            return buf.readUtf8()
        }
    }

    // ---- download + verify ---------------------------------------------------------------------------------------

    /** Downloads [rel], checks it (SHA256SUMS, package, versionCode, signing certificate) and records it as ready. Throws [UpdateException]. */
    suspend fun download(rel: ReleaseInfo): UpdatePrefs.Ready = withContext(Dispatchers.IO) {
        try {
            dir.mkdirs()
            val sums = Sha256Sums.parse(getText(rel.sumsUrl, 1_000_000))
            val part = File(dir, rel.apkName + ".part")
            val sha = MessageDigest.getInstance("SHA-256")
            val req = Request.Builder().url(rel.apkUrl).header("User-Agent", "pevv-android").build()
            client.newCall(req).execute().use { r ->
                if (!r.isSuccessful) throw UpdateException("http-${r.code}")
                val src = r.body?.byteStream() ?: throw UpdateException("empty")
                var total = 0L
                part.outputStream().use { out ->
                    val buf = ByteArray(32 * 1024)
                    while (true) {
                        val n = src.read(buf)
                        if (n < 0) break
                        total += n
                        if (total > MAX_APK) throw UpdateException("too-large")
                        sha.update(buf, 0, n)
                        out.write(buf, 0, n)
                    }
                }
            }
            val hex = Sha256Sums.hex(sha.digest())
            if (!Sha256Sums.matches(sums, rel.apkName, hex)) throw UpdateException("checksum")
            val file = File(dir, rel.apkName)
            if (file.exists()) file.delete()
            if (!part.renameTo(file)) throw UpdateException("io")
            val code = verifyApk(file)
            val ready = UpdatePrefs.Ready(file.name, rel.tag, code, hex)
            prefs.ready = ready
            prefs.lastError = ""
            cleanup(keep = file.name)
            ready
        } catch (e: Exception) {
            // Any failure leaves no unverified bytes behind.
            prefs.ready = null
            cleanup(keep = null)
            val code = (e as? UpdateException)?.code ?: "network"
            prefs.lastError = code
            throw if (e is UpdateException) e else UpdateException(code, e.message ?: code)
        }
    }

    /** Package, versionCode and signing certificate checks on the file; returns its versionCode or throws. */
    private fun verifyApk(file: File): Long {
        val pm = app.packageManager
        val flags = if (Build.VERSION.SDK_INT >= 28) PackageManager.GET_SIGNING_CERTIFICATES else @Suppress("DEPRECATION") PackageManager.GET_SIGNATURES
        val archive = pm.getPackageArchiveInfo(file.absolutePath, flags) ?: throw UpdateException("parse")
        val own = pm.getPackageInfo(app.packageName, flags)
        val reason = ApkCheck.reject(
            archive.packageName, app.packageName,
            PackageInfoCompat.getLongVersionCode(archive), PackageInfoCompat.getLongVersionCode(own),
            signers(archive), signers(own),
        )
        if (reason != null) throw UpdateException(reason)
        return PackageInfoCompat.getLongVersionCode(archive)
    }

    /** SHA-256 of each current signing certificate. */
    private fun signers(p: PackageInfo): Set<String> {
        val sigs = if (Build.VERSION.SDK_INT >= 28) p.signingInfo?.apkContentsSigners else @Suppress("DEPRECATION") p.signatures
        val md = MessageDigest.getInstance("SHA-256")
        return sigs?.map { Sha256Sums.hex(md.digest(it.toByteArray())) }?.toSet() ?: emptySet()
    }

    /** Re-checks the ready file right before installing (hash and signature again) and returns it, or null (and forgets it). */
    private fun verifiedReady(): File? {
        val r = prefs.ready ?: return null
        val f = File(dir, r.file)
        try {
            if (!f.isFile || f.parentFile?.canonicalPath != dir.canonicalPath) throw UpdateException("io")
            val md = MessageDigest.getInstance("SHA-256")
            f.inputStream().use { s -> val b = ByteArray(32 * 1024); while (true) { val n = s.read(b); if (n < 0) break; md.update(b, 0, n) } }
            if (!MessageDigest.isEqual(Sha256Sums.hex(md.digest()).toByteArray(), r.sha256.toByteArray())) throw UpdateException("checksum")
            if (verifyApk(f) != r.versionCode) throw UpdateException("version")
            return f
        } catch (e: Exception) {
            prefs.lastError = (e as? UpdateException)?.code ?: "io"
            prefs.ready = null
            cleanup(keep = null)
            return null
        }
    }

    /** Deletes everything in the download folder except [keep]. */
    fun cleanup(keep: String?) {
        dir.listFiles()?.forEach { if (it.name != keep) it.delete() }
    }

    /** At start: drop leftovers, and a ready APK that is no longer newer than the installed app. */
    fun cleanStale() {
        val r = prefs.ready
        val installed = try { PackageInfoCompat.getLongVersionCode(app.packageManager.getPackageInfo(app.packageName, 0)) } catch (_: Exception) { Long.MAX_VALUE }
        if (r != null && r.versionCode <= installed) { prefs.ready = null; cancelNotification(NOTE_READY) }
        cleanup(keep = prefs.ready?.file)
    }

    // ---- install -------------------------------------------------------------------------------------------------

    fun canRequestInstalls(): Boolean = app.packageManager.canRequestPackageInstalls()

    /** Settings screen of "Install unknown apps" for this app. */
    fun unknownSourcesIntent(): Intent =
        Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, Uri.parse("package:${app.packageName}")).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)

    /** Whether this device can update without a prompt right now (Android 12+ and we installed ourselves before). */
    fun silentPossible(): Boolean {
        val installer = try {
            if (Build.VERSION.SDK_INT >= 30) app.packageManager.getInstallSourceInfo(app.packageName).installingPackageName
            else @Suppress("DEPRECATION") app.packageManager.getInstallerPackageName(app.packageName)
        } catch (_: Exception) { null }
        return UpdatePolicy.silentInstallPossible(Build.VERSION.SDK_INT, installer, app.packageName)
    }

    fun installAllowedNow(userInitiated: Boolean) = UpdatePolicy.installAllowedNow(userInitiated, vaultInUse(), foreground)

    /**
     * Installs the ready APK through a PackageInstaller session after verifying it again. Returns false when nothing was started
     * (no ready file, it failed the re-check, or "install unknown apps" is off; the user is guided there by a notification).
     */
    fun installReady(userInitiated: Boolean): Boolean {
        if (!installAllowedNow(userInitiated)) return false
        val file = verifiedReady() ?: return false
        if (!canRequestInstalls()) {
            notifyAction(NOTE_ACTION, R.string.upd_note_allow_title, R.string.upd_note_allow_text, activityIntent(unknownSourcesIntent()))
            return false
        }
        return try {
            val pi = app.packageManager.packageInstaller
            val params = PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL)
            params.setAppPackageName(app.packageName)
            params.setSize(file.length())
            if (Build.VERSION.SDK_INT >= 31) params.setRequireUserAction(PackageInstaller.SessionParams.USER_ACTION_NOT_REQUIRED)
            val id = pi.createSession(params)
            pi.openSession(id).use { s ->
                s.openWrite("pevv-update.apk", 0, file.length()).use { out ->
                    file.inputStream().use { it.copyTo(out) }
                    s.fsync(out)
                }
                val cb = Intent(app, UpdateInstallReceiver::class.java).setAction(UpdateInstallReceiver.ACTION)
                // Mutable on purpose: the system fills in the status extras. The intent is explicit.
                val pend = PendingIntent.getBroadcast(app, id, cb, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE)
                s.commit(pend.intentSender)
            }
            true
        } catch (e: Exception) {
            prefs.lastError = "install"
            false
        }
    }

    /** Called by the receiver when the installer reports back. */
    fun onInstallStatus(status: Int, confirm: Intent?, message: String?) {
        when (status) {
            PackageInstaller.STATUS_PENDING_USER_ACTION -> {
                if (confirm == null) return
                confirm.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                if (foreground) try { app.startActivity(confirm); return } catch (_: Exception) { }
                notifyAction(NOTE_ACTION, R.string.upd_note_confirm_title, R.string.upd_note_confirm_text, activityIntent(confirm))
            }
            PackageInstaller.STATUS_SUCCESS -> { prefs.ready = null; cleanup(null) }
            else -> {
                prefs.lastError = "install-$status"
                prefs.ready = null
                cleanup(null)
                notifyAction(NOTE_ERROR, R.string.upd_note_failed_title, R.string.upd_note_failed_text, activityIntent(Intent(app, MainActivity::class.java)))
            }
        }
    }

    /** Runs an automatic install that was deferred because the vault was in use; call when the vault locks or the app is left. */
    fun retryDeferred() {
        if (prefs.mode != UpdateMode.AUTO_INSTALL || prefs.ready == null) return
        io.launch { installReady(userInitiated = false) }
    }
    // ---- the background flow -------------------------------------------------------------------------------------------

    /** Periodic check: notify (manual) or schedule the download (automatic modes). */
    suspend fun backgroundCheck() {
        val res = check()
        if (res !is CheckResult.Available) return
        val rel = res.release
        val action = UpdatePolicy.afterCheck(prefs.mode, true, prefs.ready?.tag == rel.tag, prefs.notifiedTag == rel.tag, background = true)
        when (action) {
            CheckAction.NOTIFY_AVAILABLE -> { prefs.notifiedTag = rel.tag; notifyAvailable(rel) }
            CheckAction.DOWNLOAD -> UpdateScheduler.enqueueDownload(app, prefs)
            CheckAction.NONE -> {}
        }
    }

    /** The download worker: fetch, verify, then notify or install depending on the mode. */
    suspend fun backgroundDownload() {
        val res = check()
        if (res !is CheckResult.Available) return
        val rel = res.release
        if (prefs.mode == UpdateMode.MANUAL) return
        val ready = prefs.ready?.takeIf { it.tag == rel.tag && verifiedReady() != null } ?: try { download(rel) } catch (_: UpdateException) { return }
        when (UpdatePolicy.afterDownload(prefs.mode, installAllowedNow(false))) {
            ReadyAction.INSTALL_NOW -> if (!installReady(false)) notifyReady(ready)
            ReadyAction.NOTIFY_READY, ReadyAction.DEFER_AND_NOTIFY -> notifyReady(ready)
        }
    }

    // ---- notifications -----------------------------------------------------------------------------------------------

    private fun ensureChannel() {
        val nm = app.getSystemService(NotificationManager::class.java)
        if (nm.getNotificationChannel(CHANNEL) == null) {
            nm.createNotificationChannel(NotificationChannel(CHANNEL, app.getString(R.string.upd_channel), NotificationManager.IMPORTANCE_DEFAULT))
        }
    }

    fun canNotify(): Boolean =
        Build.VERSION.SDK_INT < 33 || ContextCompat.checkSelfPermission(app, Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED

    private fun mainIntent(action: String? = null): PendingIntent {
        val i = Intent(app, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
        if (action != null) i.setAction(action)
        return PendingIntent.getActivity(app, action.hashCode(), i, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
    }

    private fun activityIntent(i: Intent): PendingIntent =
        PendingIntent.getActivity(app, i.hashCode(), i, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)

    private fun post(id: Int, title: String, text: String, pi: PendingIntent) {
        if (!canNotify()) return
        ensureChannel()
        val n = NotificationCompat.Builder(app, CHANNEL)
            .setSmallIcon(android.R.drawable.stat_sys_download_done)
            .setContentTitle(title).setContentText(text).setStyle(NotificationCompat.BigTextStyle().bigText(text))
            .setContentIntent(pi).setAutoCancel(true).setOnlyAlertOnce(true)
            .setVisibility(NotificationCompat.VISIBILITY_PUBLIC).build()
        try { NotificationManagerCompat.from(app).notify(id, n) } catch (_: SecurityException) { }
    }

    private fun notifyAction(id: Int, title: Int, text: Int, pi: PendingIntent) = post(id, app.getString(title), app.getString(text), pi)

    fun notifyAvailable(rel: ReleaseInfo) =
        post(NOTE_AVAILABLE, app.getString(R.string.upd_note_available_title), app.getString(R.string.upd_note_available_text, rel.tag), mainIntent(ACTION_OPEN_UPDATES))

    fun notifyReady(r: UpdatePrefs.Ready) =
        post(NOTE_READY, app.getString(R.string.upd_note_ready_title), app.getString(R.string.upd_note_ready_text, r.tag), mainIntent(ACTION_INSTALL_UPDATE))

    fun cancelNotification(id: Int) = NotificationManagerCompat.from(app).cancel(id)

    companion object {
        const val API = "https://api.github.com/repos/LoopyLuci/pevv"
        const val CHANNEL = "updates"
        const val ACTION_INSTALL_UPDATE = "dev.pevv.app.update.INSTALL"
        const val ACTION_OPEN_UPDATES = "dev.pevv.app.update.OPEN"
        const val NOTE_AVAILABLE = 7001
        const val NOTE_READY = 7002
        const val NOTE_ACTION = 7003
        const val NOTE_ERROR = 7004
        private const val MAX_APK = 300L * 1024 * 1024
    }
}
