package dev.pevv.app.sync

import android.content.Context
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import dev.pevv.app.core.RemoteSource
import dev.pevv.app.core.VaultFile
import dev.pevv.app.store.VaultController
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * Opt-in cloud copy of the ciphertext vault file (sync.ts + host/cloud.ts) and the live device exchange (roster.ts).
 * Everything is a no-op unless the build has the sync URL and anon key. Only the encrypted vault file ever leaves the phone.
 */
class SyncManager(
    ctx: Context,
    private val ctl: VaultController,
    val auth: Supabase,
    val relay: Relay,
    private val scope: CoroutineScope,
) {
    val enabled: Boolean get() = SyncConfig.configured

    var account by mutableStateOf(auth.currentAccount); private set
    var error by mutableStateOf<String?>(null)
    var lastSyncAt by mutableStateOf(0L); private set
    var syncing by mutableStateOf(false); private set

    private val lock = Mutex()
    private var loaded = false
    private var cloudBody: String? = null
    /** Revision of the server row the last pull or write saw: the compare-and-swap token of the next write. */
    private var cloudRev = 0L
    private var lastWritten = ""
    private var absorbed = ""
    private var foreground = false
    private var poller: Job? = null
    private var watch: Relay.CloudWatch? = null
    private var started = false

    // roster
    private var rosterLink: Relay.RosterLink? = null
    private var rosterJoined = ""
    private var rosterJob: Job? = null
    private var rosterPending: VaultFile? = null
    private val tablet = ctx.resources.configuration.smallestScreenWidthDp >= 600

    fun start() {
        if (started) return
        started = true
        ctl.onWrite { f -> scope.launch { mirror(f); publishRoster(f) } }
        ctl.onStatus { s ->
            if (s == VaultController.Status.UNLOCKED) {
                scope.launch {
                    pull()
                    ctl.rememberThisDevice(tablet)
                    rosterPending?.let { p -> if (p.id == ctl.file?.id) ctl.reconcileRemote(p, RemoteSource.PEER) }
                    rosterLink?.ask()
                }
            }
        }
        ctl.onLock { }
        auth.onAccount { a ->
            account = a
            loaded = false
            cloudBody = null
            cloudRev = 0
            if (a != null) scope.launch { pull(); startWatch() } else stopWatch()
        }
        if (enabled) {
            scope.launch { pull(); startWatch() }
            retargetRoster()
        }
    }

    fun setForeground(on: Boolean) {
        foreground = on
        if (!enabled) return
        poller?.cancel()
        if (on) {
            scope.launch { pull() }
            retargetRoster()
            poller = scope.launch {
                while (true) {
                    delay(120_000)
                    pull()
                }
            }
        }
    }

    private suspend fun startWatch() {
        stopWatch()
        val a = auth.currentAccount ?: return
        val w = Relay.CloudWatch(auth) { scope.launch { pull() } }
        if (w.start(a.userId)) watch = w else w.stop()
    }

    private fun stopWatch() {
        watch?.stop()
        watch = null
    }

    /** Fetch the account's rows now. Quiet when offline, signed out or not configured. */
    suspend fun pull() {
        if (!enabled) return
        lock.withLock {
            if (auth.currentAccount == null) { loaded = true; return }
            syncing = true
            try {
                val rows = auth.pull() ?: return
                val row = rows.firstOrNull { it.path == Supabase.SYNC_PATH }
                val body = row?.body
                cloudRev = row?.rev ?: 0
                val first = !loaded
                loaded = true
                val changed = body != cloudBody
                cloudBody = body
                lastSyncAt = System.currentTimeMillis()
                error = null
                if (changed) inbound()
                if (first || changed) mirrorLocked(ctl.file)
            } catch (e: SyncError) {
                error = e.code
            } finally {
                syncing = false
            }
        }
    }

    private suspend fun inbound() {
        val body = cloudBody ?: return
        if (body == lastWritten || body == absorbed) return
        val remote = try { VaultFile.parse(body) } catch (_: Exception) { return }
        if (ctl.prefs.vaultRevokedLocally(remote.id)) return
        val hadVault = ctl.file != null
        if (ctl.reconcileRemote(remote, RemoteSource.CLOUD)) {
            absorbed = body
            lastWritten = ctl.file?.toText() ?: body
            if (!hadVault) ctl.prefs.syncOn = true
            ctl.file?.let { if (it.toText() == body) ctl.markSynced(it) }
        }
    }

    private suspend fun mirror(file: VaultFile?) {
        if (!enabled) return
        lock.withLock { mirrorLocked(file) }
    }

    private suspend fun mirrorLocked(file: VaultFile?, attempt: Int = 0) {
        if (!loaded || auth.currentAccount == null || file == null || !ctl.prefs.syncOn) return
        val body = file.toText()
        val existing = cloudBody
        if (existing != null && existing != body) {
            try {
                val remote = VaultFile.parse(existing)
                // A device that still has an older copy (or an older key) must not overwrite the newer one: it merges first.
                if (remote.id == file.id && (remote.rev > file.rev || remote.keyEpoch > file.keyEpoch)) return
            } catch (_: Exception) { /* replace a file that is not a vault */ }
        }
        if (body == lastWritten || existing == body) return
        lastWritten = body
        try {
            val res = auth.push(Supabase.SYNC_PATH, body, cloudRev)
            if (res.ok) {
                cloudBody = body
                cloudRev = res.rev
                lastSyncAt = System.currentTimeMillis()
                error = null
                ctl.markSynced(file)
                return
            }
            lastWritten = ""
            when (res.error) {
                "conflict" -> {
                    // The server moved on since this device last looked: learn its revision, merge its copy, then write again.
                    cloudRev = res.rev
                    val theirs = res.body
                    if (theirs != null) { cloudBody = theirs; absorbed = "" }
                    if (attempt >= 2) { error = "unknown"; return }
                    if (theirs != null) inbound()
                    mirrorLocked(ctl.file, attempt + 1)
                }
                "rate-limited", "too-large", "rev-regressed" -> error = res.error
                "not-allowed", "bad-body", "not-signed-in" -> error = "denied"
                else -> error = "unknown"
            }
        } catch (e: SyncError) {
            error = if (e.code == "http-401" || e.code == "http-403") "denied" else e.code
            lastWritten = ""
        }
    }

    suspend fun setSync(on: Boolean) {
        ctl.prefs.syncOn = on
        if (on) {
            pull()
            mirror(ctl.file)
        } else {
            // Turning sync off forgets the cloud copy, so a later edit on a device that is not syncing cannot clobber it.
            lock.withLock {
                if (cloudBody != null) try { auth.remove(Supabase.SYNC_PATH) } catch (_: SyncError) { }
                cloudBody = null; cloudRev = 0; lastWritten = ""; absorbed = ""
            }
        }
    }

    suspend fun sendCode(email: String) = auth.sendOtp(email)

    suspend fun verifyCode(email: String, code: String) {
        auth.verifyOtp(email, code)
        account = auth.currentAccount
    }

    suspend fun signOut() {
        auth.signOut()
        account = null
        cloudBody = null
        cloudRev = 0
        loaded = false
    }

    /* ---------- live devices (roster.ts) ---------- */

    private fun publishRoster(f: VaultFile?) {
        val link = rosterLink ?: return
        if (f != null && f.id == rosterJoined) link.publish(f.toText())
        if (f == null || f.id != rosterJoined) retargetRoster()
    }

    fun retargetRoster() {
        if (!enabled) return
        rosterJob?.cancel()
        rosterJob = scope.launch {
            delay(400)
            val id = ctl.file?.id ?: ""
            if (id == rosterJoined && (id.isEmpty() || rosterLink != null)) {
                ctl.file?.let { rosterLink?.publish(it.toText()) }
                return@launch
            }
            rosterLink?.close()
            rosterLink = null
            rosterJoined = id
            rosterPending = null
            if (id.isEmpty()) return@launch
            try {
                val link = relay.joinRoster(id) { body ->
                    val remote = try { VaultFile.parse(body) } catch (_: Exception) { return@joinRoster }
                    if (remote.id != rosterJoined) return@joinRoster
                    rosterPending = remote
                    scope.launch { if (ctl.reconcileRemote(remote, RemoteSource.PEER) && rosterPending === remote) rosterPending = null }
                }
                if (ctl.file?.id != id) { link.close(); return@launch }
                rosterLink = link
                ctl.file?.let { link.publish(it.toText()) }
                if (ctl.isUnlocked) link.ask()
            } catch (_: SyncError) {
                rosterJoined = ""
                delay(5000)
                retargetRoster()
            }
        }
    }

    fun shutdown() {
        poller?.cancel()
        stopWatch()
        rosterLink?.close()
        relay.shutdown()
    }
}
