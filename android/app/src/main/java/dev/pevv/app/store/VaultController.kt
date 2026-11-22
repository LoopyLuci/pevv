package dev.pevv.app.store

import android.content.Context
import android.os.Handler
import android.os.Looper
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import dev.pevv.app.core.Crypto
import dev.pevv.app.core.DecryptError
import dev.pevv.app.core.Devices
import dev.pevv.app.core.Entry
import dev.pevv.app.core.EntryKinds
import dev.pevv.app.core.Reconcile
import dev.pevv.app.core.ReconcileAction
import dev.pevv.app.core.Recovery
import dev.pevv.app.core.RemoteSource
import dev.pevv.app.core.RosterSlice
import dev.pevv.app.core.Session
import dev.pevv.app.core.Totp
import dev.pevv.app.core.TotpConfig
import dev.pevv.app.core.VaultEngine
import dev.pevv.app.core.VaultFile
import dev.pevv.app.core.VaultMeta
import dev.pevv.app.core.jarr
import dev.pevv.app.core.jnum
import dev.pevv.app.core.with
import dev.pevv.app.core.jstr
import dev.pevv.app.core.jstrs
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.io.File

/** The one holder of the vault key and of decrypted items, and only while unlocked. Locking drops all of it. */
class VaultController(ctx: Context, val prefs: AppPrefs, @Suppress("unused") private val scope: CoroutineScope) {
    enum class Status { NONE, LOCKED, SECOND_FACTOR, SET_PASSWORD, UNLOCKED }

    data class Pending(val totp: Boolean = false, val passkey: Boolean = false, val usbKey: Boolean = false) {
        val any get() = totp || passkey || usbKey
    }

    class UserError(val code: String, msg: String = code) : Exception(msg)

    private val appCtx = ctx.applicationContext
    private val dir = File(appCtx.filesDir, "pevv").also { it.mkdirs() }
    private val vaultPath = File(dir, "vault.json")
    private val mutex = Mutex()
    private val main = Handler(Looper.getMainLooper())

    var status by mutableStateOf(Status.NONE); private set
    var file by mutableStateOf<VaultFile?>(null); private set
    var entries by mutableStateOf<List<Entry>>(emptyList()); private set
    var meta by mutableStateOf<VaultMeta?>(null); private set
    var totp by mutableStateOf<TotpConfig?>(null); private set
    var warnings by mutableStateOf<List<String>>(emptyList()); private set
    var pending by mutableStateOf(Pending()); private set

    /** A message code the UI shows once (`device-revoked`, ...). */
    var notice by mutableStateOf<String?>(null)

    /** Bumped on every unlock; the reveal re-authentication window starts there. */
    var revealUntil by mutableStateOf(0L); private set

    private var session: Session? = null
    private var pendingEntries: List<Entry> = emptyList()
    private var recoverySlot: String? = null
    private val writeListeners = ArrayList<(VaultFile?) -> Unit>()
    private val lockListeners = ArrayList<() -> Unit>()
    private val statusListeners = ArrayList<(Status) -> Unit>()
    private var lockRunnable: Runnable? = null

    init {
        val text = try { if (vaultPath.exists()) vaultPath.readText(Charsets.UTF_8) else null } catch (_: Exception) { null }
        if (text != null) {
            try {
                file = VaultFile.parse(text)
                status = Status.LOCKED
            } catch (_: Exception) {
            }
        }
    }

    fun onWrite(l: (VaultFile?) -> Unit) { writeListeners.add(l) }
    fun onLock(l: () -> Unit) { lockListeners.add(l) }
    fun onStatus(l: (Status) -> Unit) { statusListeners.add(l) }

    private fun changeStatus(s: Status) {
        if (status == s) return
        status = s
        for (l in statusListeners.toList()) l(s)
    }

    val isUnlocked get() = status == Status.UNLOCKED

    /** A copy of the vault key for wrapping under the biometric key. The caller wipes it. */
    fun vaultKeyCopy(): ByteArray? = session?.raw?.copyOf()

    private fun persist(f: VaultFile?) {
        if (f == null) {
            vaultPath.delete()
        } else {
            val tmp = File(dir, "vault.json.tmp")
            tmp.writeText(f.toText(), Charsets.UTF_8)
            if (!tmp.renameTo(vaultPath)) { vaultPath.delete(); tmp.renameTo(vaultPath) }
        }
        for (l in writeListeners.toList()) l(f)
    }

    private fun need(): Triple<VaultFile, Session, VaultMeta> {
        val f = file; val s = session; val m = meta
        if (status != Status.UNLOCKED || f == null || s == null || m == null) throw UserError("locked")
        return Triple(f, s, m)
    }

    private suspend fun <T> serial(block: suspend () -> T): T = withContext(Dispatchers.Default) { mutex.withLock { block() } }

    /* ---------- limiter (src/pevv/totp.ts) ---------- */

    private fun limiterKey(kind: String) = "$kind:${file?.id ?: "none"}"

    private fun guardLimiter(kind: String) {
        val (_, until) = prefs.limiter(limiterKey(kind))
        val ms = until - System.currentTimeMillis()
        if (ms > 0) throw UserError("rate-limited", "${(ms + 999) / 1000}")
    }

    private fun recordLimiter(kind: String, ok: Boolean) {
        val k = limiterKey(kind)
        if (ok) { prefs.setLimiter(k, 0, 0); return }
        val fails = prefs.limiter(k).first + 1
        prefs.setLimiter(k, fails, System.currentTimeMillis() + Totp.limiterDelay(fails))
    }

    /* ---------- lifecycle ---------- */

    suspend fun createVault(password: String, strong: Boolean = false) = serial {
        if (file != null) throw UserError("vault-exists")
        val (f, s) = VaultEngine.createVault(password, Crypto.newKdf(strong))
        file = f
        persist(f)
        openSession(s)
    }

    private fun openSession(s: Session, skipSecond: Boolean = false, passkeyDone: Boolean = false, usbDone: Boolean = false) {
        val f = file!!
        val d = try { VaultEngine.decryptAll(f, s) } catch (e: DecryptError) { s.end(); throw e }
        if (prefs.deviceId in d.meta.revokedDevices) {
            s.end()
            prefs.markRevoked(f.id)
            destroyInner()
            notice = "device-revoked"
            return
        }
        prefs.clearRevoked(f.id)
        session?.end()
        session = s
        val need = Pending(
            totp = d.meta.require.totp && !skipSecond,
            passkey = d.meta.require.passkey && !skipSecond && !passkeyDone,
            usbKey = d.meta.require.usbKey == true && !skipSecond && !usbDone,
        )
        meta = d.meta; totp = d.totp; warnings = d.warnings
        if (need.any) {
            pending = need
            entries = emptyList()
            pendingEntries = d.entries
            changeStatus(Status.SECOND_FACTOR)
            return
        }
        finishUnlock(d.entries)
    }

    private fun finishUnlock(list: List<Entry>) {
        pendingEntries = emptyList()
        pending = Pending()
        entries = list
        revealUntil = System.currentTimeMillis() + prefs.revealReauthSeconds * 1000L
        changeStatus(Status.UNLOCKED)
        touch()
    }

    suspend fun unlockPassword(password: String) = serial {
        val f = file ?: throw UserError("no-vault")
        guardLimiter("pw")
        try {
            val s = VaultEngine.unlockWithPassword(f, password)
            recordLimiter("pw", true)
            openSession(s)
        } catch (e: DecryptError) {
            recordLimiter("pw", false)
            throw e
        }
    }

    /** Biometric quick unlock hands back the vault key itself; the second-factor gates still apply. */
    suspend fun unlockWithKey(raw: ByteArray) = serial {
        val f = file ?: throw UserError("no-vault")
        val s = Session(raw)
        // A key that does not open this vault (replaced vault, damaged copy) must fail closed.
        try { VaultEngine.readMeta(f, s) } catch (e: DecryptError) { s.end(); throw e }
        openSession(s)
    }

    suspend fun unlockUsbKey(text: String) = serial {
        val f = file ?: throw UserError("no-vault")
        if (f.slots.none { it.type == "usb-key" }) throw UserError("no-usb-slot")
        guardLimiter("usb")
        try {
            val s = VaultEngine.unlockWithUsbKey(f, text)
            recordLimiter("usb", true)
            openSession(s, usbDone = true)
        } catch (e: DecryptError) {
            recordLimiter("usb", false)
            throw e
        }
    }

    suspend fun unlockPrf(credId: String, output: ByteArray) = serial {
        val f = file ?: throw UserError("no-vault")
        val s = VaultEngine.unlockWithPrf(f, credId, output)
        openSession(s, passkeyDone = true)
    }

    /** A recovery code, recovery key or kit opens the vault but then forces a new master password. */
    suspend fun unlockRecoveryCode(code: String) = serial {
        val f = file ?: throw UserError("no-vault")
        guardLimiter("rc")
        try {
            val (s, slotId) = VaultEngine.unlockWithRecoveryCode(f, code)
            recordLimiter("rc", true)
            beginSetPassword(f, s, slotId)
        } catch (e: DecryptError) {
            recordLimiter("rc", false)
            throw e
        }
    }

    suspend fun unlockRecoveryKey(key: String) = serial {
        val f = file ?: throw UserError("no-vault")
        guardLimiter("rk")
        try {
            val s = VaultEngine.unlockWithRecoveryKey(f, key)
            recordLimiter("rk", true)
            beginSetPassword(f, s, null)
        } catch (e: DecryptError) {
            recordLimiter("rk", false)
            throw e
        }
    }

    suspend fun unlockRecoveryKit(kitText: String, passphrase: String) = serial {
        val f = file ?: throw UserError("no-vault")
        guardLimiter("kit")
        try {
            val key = Recovery.openKit(kitText, passphrase)
            val s = VaultEngine.unlockWithRecoveryKey(f, key)
            recordLimiter("kit", true)
            beginSetPassword(f, s, null)
        } catch (e: DecryptError) {
            recordLimiter("kit", false)
            throw e
        }
    }

    private fun beginSetPassword(f: VaultFile, s: Session, slotId: String?) {
        val d = VaultEngine.decryptAll(f, s)
        session?.end()
        session = s
        pendingEntries = d.entries
        recoverySlot = slotId
        meta = d.meta; totp = d.totp; warnings = d.warnings
        changeStatus(Status.SET_PASSWORD)
    }

    suspend fun setPasswordAfterRecovery(newPassword: String) = serial {
        val f = file; val s = session; val m = meta
        if (status != Status.SET_PASSWORD || f == null || s == null || m == null) throw UserError("not-recovering")
        var next = VaultEngine.changePassword(f, s, m, newPassword)
        recoverySlot?.let { next = VaultEngine.consumeSlot(next, s, m, it) }
        recoverySlot = null
        file = next
        persist(next)
        val d = VaultEngine.decryptAll(next, s)
        meta = d.meta
        if (d.meta.require.totp || d.meta.require.usbKey == true) {
            pending = Pending(totp = d.meta.require.totp, usbKey = d.meta.require.usbKey == true)
            changeStatus(Status.SECOND_FACTOR)
        } else finishUnlock(pendingEntries)
    }

    suspend fun verifySecondTotp(code: String) = serial {
        val f = file; val s = session; val m = meta; val t = totp
        if (status != Status.SECOND_FACTOR || f == null || s == null || t == null || m == null) throw UserError("not-waiting")
        guardLimiter("totp")
        val step = Totp.verify(t, code, System.currentTimeMillis(), 1, m.json.get("totpLastStep")?.let { (it as? JsonPrimitive)?.content?.toLongOrNull() })
        recordLimiter("totp", step != null)
        if (step == null) throw UserError("bad-code")
        val nm = m.with(mapOf("totpLastStep" to jnum(step)))
        val nf = VaultEngine.saveMeta(f, s, nm)
        file = nf; meta = nm
        persist(nf)
        pending = pending.copy(totp = false)
        if (!pending.any) finishUnlock(pendingEntries)
    }

    suspend fun verifySecondUsbKey(text: String) = serial {
        val f = file; val s = session; val m = meta
        if (status != Status.SECOND_FACTOR || f == null || s == null || m == null) throw UserError("not-waiting")
        guardLimiter("usb")
        val ok = try { VaultEngine.checkUsbKeyFactor(f, s, m, text) } catch (e: IllegalArgumentException) { throw UserError("bad-key-file", e.message ?: "") }
        recordLimiter("usb", ok)
        if (!ok) throw UserError("wrong-key-file")
        pending = pending.copy(usbKey = false)
        if (!pending.any) finishUnlock(pendingEntries)
    }

    /** The passkey second factor was checked by the caller (signature and rpId verified). */
    suspend fun passkeyGatePassed(credId: String, signCount: Long) = serial {
        val f = file
        if (status != Status.SECOND_FACTOR || f == null) throw UserError("not-waiting")
        val next = f.with(mapOf("passkeys" to jarr(f.passkeys.map { p ->
            val o = p as? JsonObject
            if (o != null && (o["id"] as? JsonPrimitive)?.content == credId) o.with("signCount" to jnum(signCount), "lastUsed" to jnum(System.currentTimeMillis())) else p
        })))
        file = next
        persist(next)
        pending = pending.copy(passkey = false)
        if (!pending.any) finishUnlock(pendingEntries)
    }

    fun lock() = lockNow()

    private fun lockNow() {
        lockRunnable?.let { main.removeCallbacks(it) }
        session?.end()
        session = null
        entries = emptyList(); meta = null; totp = null; warnings = emptyList(); pending = Pending()
        pendingEntries = emptyList(); recoverySlot = null
        revealUntil = 0
        changeStatus(if (file != null) Status.LOCKED else Status.NONE)
        for (l in lockListeners.toList()) l()
    }

    /** Reset the idle timer (called on every user action while unlocked). */
    fun touch() {
        lockRunnable?.let { main.removeCallbacks(it) }
        val s = prefs.idleSeconds
        if (s <= 0 || status == Status.NONE || status == Status.LOCKED) return
        val r = Runnable { lockNow() }
        lockRunnable = r
        main.postDelayed(r, s * 1000L)
    }

    private var bgLock: Runnable? = null

    /** Lock after [ms] in the background (the process may be frozen, so the activity also checks the clock on return). */
    fun lockAfter(ms: Long) {
        cancelBackgroundLock()
        if (status == Status.NONE || status == Status.LOCKED) return
        if (ms <= 0) { lockNow(); return }
        val r = Runnable { lockNow() }
        bgLock = r
        main.postDelayed(r, ms)
    }

    fun cancelBackgroundLock() {
        bgLock?.let { main.removeCallbacks(it) }
        bgLock = null
    }

    fun destroyVault() {
        destroyInner()
    }

    private fun destroyInner() {
        lockNow()
        file = null
        changeStatus(Status.NONE)
        persist(null)
    }

    /** Re-authentication window for revealing secrets. */
    fun canReveal(): Boolean = System.currentTimeMillis() < revealUntil

    fun grantReveal() { revealUntil = System.currentTimeMillis() + prefs.revealReauthSeconds * 1000L }

    /** Check the master password again (reveal and destructive actions). */
    suspend fun reauth(password: String): Boolean = serial {
        val f = file ?: return@serial false
        guardLimiter("pw")
        try {
            VaultEngine.unlockWithPassword(f, password).end()
            recordLimiter("pw", true)
            grantReveal()
            true
        } catch (_: DecryptError) {
            recordLimiter("pw", false)
            false
        }
    }

    /* ---------- items ---------- */

    private fun adopt(f: VaultFile, m: VaultMeta) { file = f; meta = m; persist(f) }

    suspend fun saveEntry(id: String?, data: JsonObject): Entry = serial {
        val (f, s, m) = need()
        val (nf, nm, e) = VaultEngine.putEntry(f, s, m, id, data)
        adopt(nf, nm)
        entries = if (id != null) entries.map { if (it.id == id) e else it } else entries + e
        touch()
        e
    }

    suspend fun saveEntries(list: List<JsonObject>): Int = serial {
        var (f, s, m) = need()
        val added = ArrayList<Entry>()
        for (d in list) {
            val r = VaultEngine.putEntry(f, s, m, null, d)
            f = r.first; m = r.second; added.add(r.third)
        }
        adopt(f, m)
        entries = entries + added
        touch()
        added.size
    }

    suspend fun deleteEntry(id: String) = serial {
        val (f, s, m) = need()
        val (nf, nm) = VaultEngine.removeEntry(f, s, m, id)
        adopt(nf, nm)
        entries = entries.filter { it.id != id }
        touch()
    }

    /** Edit fields, keeping the old secret values in the item's history. */
    suspend fun editEntry(e: Entry, changes: Map<String, JsonElement?>): Entry =
        saveEntry(e.id, EntryKinds.applyEdit(e.data, changes))

    suspend fun updateMeta(patch: Map<String, JsonElement?>) = serial {
        val (f, s, m) = need()
        writeMetaInner(f, s, m, patch)
    }

    private fun writeMetaInner(f: VaultFile, s: Session, m: VaultMeta, patch: Map<String, JsonElement?>) {
        val nm = m.with(patch)
        val nf = VaultEngine.saveMeta(f, s, nm)
        adopt(nf, nm)
    }

    suspend fun addFolder(name: String) = updateMeta(mapOf("folders" to jstrs((meta!!.folders + name.trim().take(40)).distinct())))

    /* ---------- account security ---------- */

    suspend fun changePassword(current: String, next: String) = serial {
        val (f, s, m) = need()
        VaultEngine.unlockWithPassword(f, current).end()
        val nf = VaultEngine.changePassword(f, s, m, next)
        adopt(nf, m)
    }

    suspend fun newRecoveryCodes(): List<String> = serial {
        val (f, s, m) = need()
        val (nf, codes) = VaultEngine.replaceRecoveryCodes(f, s, m)
        adopt(nf, m)
        codes
    }

    suspend fun newRecoveryKey(): String = serial {
        val (f, s, m) = need()
        val (nf, key) = VaultEngine.replaceRecoveryKey(f, s, m)
        adopt(nf, m)
        key
    }

    suspend fun setTotpGate(cfg: TotpConfig?) = serial {
        val (f, s, m) = need()
        val (nf, nm) = VaultEngine.setTotp(f, s, m, cfg)
        adopt(nf, nm)
        totp = cfg
    }

    suspend fun addUsbKey(name: String, unlock: Boolean): String = serial {
        val (f, s, m) = need()
        val (nf, nm, text) = VaultEngine.addUsbKey(f, s, m, name, unlock)
        adopt(nf, nm)
        text
    }

    suspend fun removeUsbKey(id: String) = serial {
        val (f, s, m) = need()
        val (nf, nm) = VaultEngine.removeUsbKey(f, s, m, id)
        adopt(nf, nm)
    }

    suspend fun setRequireUsbKey(on: Boolean) = serial {
        val (f, s, m) = need()
        val (nf, nm) = VaultEngine.setRequireUsbKey(f, s, m, on)
        adopt(nf, nm)
    }

    suspend fun addPrfSlot(credId: String, prfOutput: ByteArray, record: JsonObject) = serial {
        val (f, s, m) = need()
        var nf = VaultEngine.addPrfSlot(f, s, m, credId, prfOutput)
        nf = nf.with(mapOf("passkeys" to jarr(nf.passkeys.filter { (it as? JsonObject)?.get("id")?.let { x -> (x as? JsonPrimitive)?.content } != credId } + record)))
        adopt(nf, m)
    }

    /** A passkey that is only a second factor (no unlock slot). */
    suspend fun addPasskeyRecord(record: JsonObject) = serial {
        val (f, _, m) = need()
        val id = (record["id"] as? JsonPrimitive)?.content
        val list = f.passkeys.filter { (it as? JsonObject)?.get("id")?.let { x -> (x as? JsonPrimitive)?.content } != id } + record
        adopt(VaultEngine.commit(f, session!!, m, mapOf("passkeys" to jarr(list))), m)
    }

    suspend fun removePasskeyRecord(credId: String) = serial {
        val (f, s, m) = need()
        adopt(VaultEngine.removePrfSlots(f, s, m, credId), m)
    }

    suspend fun exportPortable(password: String): String = serial {
        val (f, _, _) = need()
        dev.pevv.app.core.Json.encode(VaultEngine.exportPortable(f, password))
    }

    suspend fun verifyExportRoundTrip(text: String, password: String) = serial { VaultEngine.openExport(text, password) }

    /* ---------- vault copies (QR, file, cloud, live devices) ---------- */

    /** Install a vault that arrived by QR, file or sync. The old one on this device is replaced; the caller confirms that. */
    suspend fun installVaultCopy(remote: VaultFile) = serial {
        VaultFile.validate(remote)
        if (prefs.vaultRevokedLocally(remote.id)) throw UserError("device-revoked")
        lockNow()
        file = remote
        persist(remote)
        changeStatus(Status.LOCKED)
    }

    private fun adoptRemoteInner(remote: VaultFile): Boolean {
        if (prefs.vaultRevokedLocally(remote.id)) return false
        val c = file
        if (c != null && (remote.id != c.id || remote.rev <= c.rev)) return false
        file = remote
        persist(remote)
        if (status == Status.NONE) changeStatus(Status.LOCKED)
        val s = session
        if (status == Status.UNLOCKED && s != null) {
            try {
                val d = VaultEngine.decryptAll(remote, s)
                if (prefs.deviceId in d.meta.revokedDevices) {
                    prefs.markRevoked(remote.id)
                    destroyInner()
                    notice = "device-revoked"
                    return true
                }
                entries = d.entries; meta = d.meta; totp = d.totp; warnings = d.warnings
            } catch (_: DecryptError) {
                lockNow()
            }
        }
        return true
    }

    /**
     * Fold another copy of this vault into the open one (the rules of `reconcileRemote` in store.ts, see [Reconcile]).
     * A higher revision replaces items when allowed; the device list is always a union.
     */
    suspend fun reconcileRemote(remote: VaultFile, source: RemoteSource): Boolean = serial {
        try { VaultFile.validate(remote) } catch (_: IllegalArgumentException) { return@serial false }
        val local = file
        val unlocked = status == Status.UNLOCKED && session != null
        val action = Reconcile.decide(
            hasLocal = local != null, localId = local?.id ?: "", localRev = local?.rev ?: 0, remoteId = remote.id, remoteRev = remote.rev,
            unlocked = unlocked, source = source, prefSync = prefs.syncOn, revokedLocally = prefs.vaultRevokedLocally(remote.id),
        )
        when (action) {
            ReconcileAction.IGNORE -> false
            ReconcileAction.ADOPT -> {
                val before = meta?.let { RosterSlice(it.devices, it.revokedDevices) }
                val ok = adoptRemoteInner(remote)
                if (ok && before != null && status == Status.UNLOCKED) {
                    val left = RosterSlice(meta!!.devices, meta!!.revokedDevices)
                    val merged = Devices.mergeRoster(left, before)
                    if (!Devices.sameRoster(left, merged)) writeRoster(merged)
                    checkSelfRevoked()
                }
                ok
            }
            ReconcileAction.MERGE_ROSTER -> {
                val s = session!!
                val rm = try { VaultEngine.readMeta(remote, s) } catch (_: DecryptError) { return@serial false }
                val left = RosterSlice(meta!!.devices, meta!!.revokedDevices)
                val merged = Devices.mergeRoster(left, RosterSlice(rm.devices, rm.revokedDevices))
                if (!Devices.sameRoster(left, merged)) writeRoster(merged)
                checkSelfRevoked()
                true
            }
        }
    }

    private fun writeRoster(r: RosterSlice) {
        val (f, s, m) = Triple(file!!, session!!, meta!!)
        writeMetaInner(f, s, m, mapOf("devices" to Devices.devicesJson(r.devices), "revokedDevices" to jstrs(r.revokedDevices)))
    }

    private fun checkSelfRevoked() {
        if (prefs.deviceId in (meta?.revokedDevices ?: emptyList())) {
            prefs.markRevoked(file!!.id)
            destroyInner()
            notice = "device-revoked"
        }
    }

    /** Register this phone on the vault and refresh last-opened, at most once an hour. */
    suspend fun rememberThisDevice(tablet: Boolean) = serial {
        if (status != Status.UNLOCKED || session == null) return@serial
        val m = meta!!
        val id = prefs.deviceId
        if (id in m.revokedDevices) {
            prefs.markRevoked(file!!.id)
            destroyInner()
            notice = "device-revoked"
            return@serial
        }
        val prev = m.devices.firstOrNull { it.id == id }
        val mine = prefs.describeDevice(prev, tablet)
        if (!Devices.deviceNeedsWrite(prev, mine)) return@serial
        val devices = Devices.mergeDevices(m.devices, listOf(mine)).filter { it.id !in m.revokedDevices }
        writeMetaInner(file!!, session!!, m, mapOf("devices" to Devices.devicesJson(devices)))
    }

    suspend fun renameThisDevice(name: String, tablet: Boolean) {
        val n = Devices.cleanDeviceName(name)
        if (n.isEmpty()) throw UserError("device-name")
        prefs.customDeviceName = n
        serial {
            val (f, s, m) = need()
            val prev = m.devices.firstOrNull { it.id == prefs.deviceId }
            val mine = prefs.describeDevice(prev, tablet).copy(name = n)
            writeMetaInner(f, s, m, mapOf("devices" to Devices.devicesJson(Devices.mergeDevices(m.devices, listOf(mine)))))
        }
    }

    /** Forget another device. It wipes its copy the next time that copy unlocks or syncs. */
    suspend fun revokeDevice(id: String) = serial {
        val (f, s, m) = need()
        if (id == prefs.deviceId) throw UserError("revoke-self")
        val revoked = (m.revokedDevices + id).distinct().take(100)
        val devices = m.devices.filter { it.id != id }
        writeMetaInner(f, s, m, mapOf("devices" to Devices.devicesJson(devices), "revokedDevices" to jstrs(revoked)))
    }

    /** User-confirmed association of an Android app with a vault login (autofill). Sealed in the meta, ignored by other clients. */
    suspend fun linkApp(pkg: String, entryId: String) = serial {
        val (f, s, m) = need()
        val cur = (m.json["androidAppLinks"] as? JsonObject) ?: JsonObject(emptyMap())
        val next = JsonObject(LinkedHashMap(cur) + (pkg to jstr(entryId)))
        writeMetaInner(f, s, m, mapOf("androidAppLinks" to next))
    }

    fun appLinks(): Map<String, String> =
        (meta?.json?.get("androidAppLinks") as? JsonObject)?.mapNotNull { (k, v) -> (v as? JsonPrimitive)?.takeIf { it.isString }?.content?.let { k to it } }?.toMap() ?: emptyMap()

}
