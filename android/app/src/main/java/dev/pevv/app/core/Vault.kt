package dev.pevv.app.core

import dev.pevv.app.core.Bytes.b64
import dev.pevv.app.core.Bytes.unb64
import dev.pevv.app.core.Bytes.utf8
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/** The unwrapped vault key, held in memory only while unlocked. */
class Session(val raw: ByteArray) {
    init {
        require(raw.size == 32) { "vault key must be 256 bits" }
    }

    fun end() = Bytes.wipe(raw)
}

class Decrypted(val entries: List<Entry>, val meta: VaultMeta, val totp: TotpConfig?, val warnings: List<String>)

/** Same new-id shape as `newId()` in model.ts: 12 random bytes as 24 hex characters. */
fun newId(): String = Bytes.hex(Bytes.random(12))

/** The vault engine: pure functions over [VaultFile] and a [Session]. A port of src/pevv/vault.ts. */
object VaultEngine {
    fun createVault(password: String, kdf: Kdf? = null, now: Long = System.currentTimeMillis()): Pair<VaultFile, Session> {
        val id = newId()
        val params = kdf ?: Crypto.newKdf()
        val session = Session(Crypto.newVaultKey())
        val slotId = newId()
        val kek = Crypto.passwordKek(password, params)
        val file = VaultFile(buildJsonObject {
            put("format", VAULT_FORMAT)
            put("v", 1)
            put("id", id)
            put("created", now)
            put("updated", now)
            put("rev", 1)
            put("kdf", params.toJson())
            put("slots", JsonArray(listOf(Slot.password(slotId, Crypto.wrapVaultKey(kek, session.raw, id, slotId)).json)))
            put("passkeys", JsonArray(emptyList()))
            put("require", buildJsonObject { put("totp", false); put("passkey", false) })
            put("totp", jnull)
            put("meta", Crypto.sealJson(session.raw, VaultMeta.DEFAULT.json, Crypto.Aad.meta(id, 1)).toJson())
            put("entries", JsonArray(emptyList()))
        })
        Bytes.wipe(kek)
        return file to session
    }

    private fun unwrapWith(kek: ByteArray, file: VaultFile, s: Slot): Session? = try {
        Session(Crypto.unwrapVaultKey(kek, s.wrapped, file.id, s.id))
    } catch (_: DecryptError) {
        null
    }

    fun unlockWithPassword(file: VaultFile, password: String): Session {
        val kek = Crypto.passwordKek(password, file.kdf)
        try {
            for (s in file.slots) {
                if (s.type != "password") continue
                unwrapWith(kek, file, s)?.let { return it }
            }
        } finally {
            Bytes.wipe(kek)
        }
        throw DecryptError("wrong master password")
    }

    fun prfKek(prfOutput: ByteArray, salt: String): ByteArray = Crypto.hkdf(prfOutput, unb64(salt), Crypto.INFO_PRF)

    fun unlockWithPrf(file: VaultFile, credId: String, prfOutput: ByteArray): Session {
        val slot = file.slots.firstOrNull { it.type == "prf" && it.credId == credId } ?: throw DecryptError("this passkey is not enrolled for unlock")
        return Session(Crypto.unwrapVaultKey(prfKek(prfOutput, slot.salt), slot.wrapped, file.id, slot.id))
    }

    fun usbKek(secret: ByteArray, salt: String): ByteArray = Crypto.hkdf(secret, unb64(salt), Crypto.INFO_USB)

    fun unlockWithUsbKey(file: VaultFile, keyFileText: String): Session {
        val secret = UsbKeyFile.parse(keyFileText).second
        for (s in file.slots) {
            if (s.type != "usb-key") continue
            unwrapWith(usbKek(secret, s.salt), file, s)?.let { return it }
        }
        throw DecryptError("this key file does not open the vault")
    }

    fun unlockWithRecoveryCode(file: VaultFile, code: String): Pair<Session, String> {
        if (Recovery.normalizeCode(code).length != 20) throw DecryptError("recovery codes have 20 characters")
        for (s in file.slots) {
            if (s.type != "recovery-code") continue
            if (Recovery.codeHash(code, s.salt) != s.hash) continue
            return Session(Crypto.unwrapVaultKey(Recovery.codeKek(code, s.salt), s.wrapped, file.id, s.id)) to s.id
        }
        throw DecryptError("unknown or already used recovery code")
    }

    fun unlockWithRecoveryKey(file: VaultFile, key: String): Session {
        for (s in file.slots) {
            if (s.type != "recovery-key") continue
            unwrapWith(Recovery.recoveryKeyKek(key, s.salt), file, s)?.let { return it }
        }
        throw DecryptError("recovery key does not match this vault")
    }

    /** The device id stamped into the sealed meta of every write, so other devices can reject a write from a revoked one. */
    @Volatile
    var writerId: String? = null

    /** Bump the revision and re-seal meta (the meta AAD is bound to the revision). */
    fun commit(file: VaultFile, session: Session, meta0: VaultMeta, patch: Map<String, JsonElement?> = emptyMap(), now: Long = System.currentTimeMillis()): VaultFile {
        val rev = file.rev + 1
        val meta = writerId?.let { meta0.with(mapOf("lastWriter" to jstr(it))) } ?: meta0
        val req = meta.require
        val next = file.with(patch).with(mapOf("rev" to jnum(rev), "updated" to jnum(now)))
        return next.with(
            mapOf(
                "require" to req.toJson(),
                "meta" to Crypto.sealJson(session.raw, meta.json, Crypto.Aad.meta(file.id, rev)).toJson(),
            ),
        )
    }

    fun readMeta(file: VaultFile, session: Session): VaultMeta {
        val o = Crypto.openJson(session.raw, file.meta, Crypto.Aad.meta(file.id, file.rev)) as? JsonObject ?: throw DecryptError("damaged record")
        return VaultMeta.withDefaults(o)
    }

    fun decryptAll(file: VaultFile, session: Session): Decrypted {
        val meta = readMeta(file, session)
        val warnings = ArrayList<String>()
        val entries = ArrayList<Entry>()
        val index = meta.index
        for (r in file.entries) {
            try {
                val data = Crypto.openJson(session.raw, r.sealed, Crypto.Aad.entry(file.id, r.id, r.ver)) as? JsonObject ?: throw DecryptError()
                entries.add(Entry(r.id, r.ver, data))
            } catch (_: DecryptError) {
                warnings.add("entry ${r.id.take(6)} could not be decrypted")
            }
            if (index[r.id] != r.ver) warnings.add("entry ${r.id.take(6)} does not match the vault index (modified outside PEVV?)")
        }
        val have = file.entries.map { it.id }.toSet()
        for (id in index.keys) if (id !in have) warnings.add("entry ${id.take(6)} is missing from the file")
        val fr = file.require
        val mr = meta.require
        if (mr.totp != fr.totp || mr.passkey != fr.passkey || (mr.usbKey == true) != (fr.usbKey == true)) {
            warnings.add("second-factor settings in the file were altered; using the encrypted copy")
        }
        var totp: TotpConfig? = null
        file.totp?.let { totp = TotpConfig.from(Crypto.openJson(session.raw, it, Crypto.Aad.totp(file.id))) }
        if (mr.totp && totp == null) warnings.add("TOTP is required but its secret is missing")
        return Decrypted(entries, meta, totp, warnings)
    }

    fun putEntry(file: VaultFile, session: Session, meta: VaultMeta, id: String?, data: JsonObject): Triple<VaultFile, VaultMeta, Entry> {
        val eid = id ?: newId()
        val prev = file.entries.firstOrNull { it.id == eid }
        val ver = (prev?.ver ?: 0) + 1
        val rec = EntryRecord.of(eid, ver, Crypto.sealJson(session.raw, data, Crypto.Aad.entry(file.id, eid, ver)))
        val entries: List<JsonElement> = if (prev != null) file.entries.map { if (it.id == eid) rec.json else it.json } else file.entries.map { it.json } + rec.json
        val index = LinkedHashMap<String, JsonElement>(meta.json.obj("index") ?: JsonObject(emptyMap()))
        index[eid] = jnum(ver)
        val nextMeta = meta.with(mapOf("index" to JsonObject(index)))
        return Triple(commit(file, session, nextMeta, mapOf("entries" to JsonArray(entries))), nextMeta, Entry(eid, ver, data))
    }

    fun removeEntry(file: VaultFile, session: Session, meta: VaultMeta, id: String): Pair<VaultFile, VaultMeta> {
        val index = LinkedHashMap<String, JsonElement>(meta.json.obj("index") ?: JsonObject(emptyMap()))
        index.remove(id)
        val nextMeta = meta.with(mapOf("index" to JsonObject(index)))
        val entries = JsonArray(file.entries.filter { it.id != id }.map { it.json })
        return commit(file, session, nextMeta, mapOf("entries" to entries)) to nextMeta
    }

    fun saveMeta(file: VaultFile, session: Session, meta: VaultMeta): VaultFile = commit(file, session, meta)

    private fun slotsJson(slots: List<Slot>) = JsonArray(slots.map { it.json })

    fun changePassword(file: VaultFile, session: Session, meta: VaultMeta, password: String, kdf: Kdf? = null): VaultFile {
        val cur = file.kdf
        val strong = cur is Kdf.Argon2id && cur.m > 65_536
        val params = kdf ?: Crypto.newKdf(strong)
        val slotId = newId()
        val kek = Crypto.passwordKek(password, params)
        val slots = listOf(Slot.password(slotId, Crypto.wrapVaultKey(kek, session.raw, file.id, slotId))) + file.slots.filter { it.type != "password" }
        Bytes.wipe(kek)
        return commit(file, session, meta, mapOf("kdf" to params.toJson(), "slots" to slotsJson(slots)))
    }

    fun addPrfSlot(file: VaultFile, session: Session, meta: VaultMeta, credId: String, prfOutput: ByteArray): VaultFile {
        val salt = b64(Bytes.random(32))
        val id = newId()
        val wrapped = Crypto.wrapVaultKey(prfKek(prfOutput, salt), session.raw, file.id, id)
        val slots = file.slots.filter { !(it.type == "prf" && it.credId == credId) } + Slot.prf(id, credId, salt, wrapped)
        return commit(file, session, meta, mapOf("slots" to slotsJson(slots)))
    }

    fun removePrfSlots(file: VaultFile, session: Session, meta: VaultMeta, credId: String): VaultFile {
        val slots = file.slots.filter { !(it.type == "prf" && it.credId == credId) }
        val passkeys = JsonArray(file.passkeys.filter { (it as? JsonObject)?.str("id") != credId })
        return commit(file, session, meta, mapOf("slots" to slotsJson(slots), "passkeys" to passkeys))
    }

    fun replaceRecoveryCodes(file: VaultFile, session: Session, meta: VaultMeta, count: Int = Recovery.COUNT): Pair<VaultFile, List<String>> {
        val codes = ArrayList<String>()
        val slots = ArrayList(file.slots.filter { it.type != "recovery-code" })
        repeat(count) {
            val code = Recovery.newRecoveryCode()
            val salt = b64(Bytes.random(16))
            val id = newId()
            slots.add(Slot.recoveryCode(id, salt, Recovery.codeHash(code, salt), Crypto.wrapVaultKey(Recovery.codeKek(code, salt), session.raw, file.id, id)))
            codes.add(code)
        }
        return commit(file, session, meta, mapOf("slots" to slotsJson(slots))) to codes
    }

    fun consumeSlot(file: VaultFile, session: Session, meta: VaultMeta, slotId: String): VaultFile =
        commit(file, session, meta, mapOf("slots" to slotsJson(file.slots.filter { it.id != slotId })))

    fun replaceRecoveryKey(file: VaultFile, session: Session, meta: VaultMeta): Pair<VaultFile, String> {
        val key = Recovery.newRecoveryKey()
        val salt = b64(Bytes.random(16))
        val id = newId()
        val slots = file.slots.filter { it.type != "recovery-key" } +
            Slot.recoveryKey(id, salt, Crypto.wrapVaultKey(Recovery.recoveryKeyKek(key, salt), session.raw, file.id, id))
        return commit(file, session, meta, mapOf("slots" to slotsJson(slots))) to key
    }

    fun setTotp(file: VaultFile, session: Session, meta: VaultMeta, cfg: TotpConfig?): Pair<VaultFile, VaultMeta> {
        val r = meta.require
        // A new (or removed) authenticator starts a new trust epoch: nothing remembered about the old one counts.
        val epoch = SecondFactorTrust.epochOf(meta) + 1
        val nextMeta = meta.with(mapOf("require" to r.copy(totp = cfg != null).toJson(), "totpLastStep" to jnull, "trustEpoch" to jnum(epoch)))
        val totp = cfg?.let { Crypto.sealJson(session.raw, it.toJson(), Crypto.Aad.totp(file.id)).toJson() } ?: jnull
        return commit(file, session, nextMeta, mapOf("totp" to totp)) to nextMeta
    }

    fun addUsbKey(file: VaultFile, session: Session, meta: VaultMeta, name: String, unlock: Boolean): Triple<VaultFile, VaultMeta, String> {
        val kf = UsbKeyFile.create(file.id)
        val id = newId()
        val label = name.trim().take(60).ifEmpty { "USB key" }
        if (unlock) {
            val salt = b64(Bytes.random(32))
            val wrapped = Crypto.wrapVaultKey(usbKek(kf.secret, salt), session.raw, file.id, id)
            val slots = file.slots + Slot.usbKey(id, label, salt, wrapped)
            return Triple(commit(file, session, meta, mapOf("slots" to slotsJson(slots))), meta, kf.text)
        }
        val gate = UsbKeyGate(id, label, UsbKeyFile.gateCheck(kf.secret), System.currentTimeMillis())
        val nextMeta = meta.with(mapOf("usbKeys" to JsonArray(meta.usbKeys.map { it.toJson() } + gate.toJson())))
        return Triple(commit(file, session, nextMeta), nextMeta, kf.text)
    }

    fun removeUsbKey(file: VaultFile, session: Session, meta: VaultMeta, id: String): Pair<VaultFile, VaultMeta> {
        val keys = meta.usbKeys.filter { it.id != id }
        val r = meta.require
        val nextMeta = meta.with(mapOf("usbKeys" to JsonArray(keys.map { it.toJson() }), "require" to r.copy(usbKey = if (keys.isNotEmpty()) r.usbKey == true else false).toJson()))
        return commit(file, session, nextMeta, mapOf("slots" to slotsJson(file.slots.filter { it.id != id }))) to nextMeta
    }

    fun setRequireUsbKey(file: VaultFile, session: Session, meta: VaultMeta, on: Boolean): Pair<VaultFile, VaultMeta> {
        val nextMeta = meta.with(mapOf("require" to meta.require.copy(usbKey = on).toJson()))
        return commit(file, session, nextMeta) to nextMeta
    }

    fun checkUsbKeyFactor(file: VaultFile, session: Session, meta: VaultMeta, keyFileText: String): Boolean {
        val secret = UsbKeyFile.parse(keyFileText).second
        for (g in meta.usbKeys) if (UsbKeyFile.gateMatches(secret, g.check)) return true
        for (s in file.slots.filter { it.type == "usb-key" }) {
            try {
                val raw = Crypto.unwrapVaultKey(usbKek(secret, s.salt), s.wrapped, file.id, s.id)
                val same = Bytes.ctEqual(raw, session.raw)
                Bytes.wipe(raw)
                if (same) return true
            } catch (_: DecryptError) {
            }
        }
        return false
    }

    data class RecoveryStatus(val codes: Int, val key: Boolean, val prf: Int, val usb: Int)

    fun recoveryStatus(file: VaultFile) = RecoveryStatus(
        file.slots.count { it.type == "recovery-code" }, file.slots.any { it.type == "recovery-key" },
        file.slots.count { it.type == "prf" }, file.slots.count { it.type == "usb-key" },
    )

    /* ---------- portable export ---------- */

    fun peekExport(text: String): Int = try {
        val j = Json.parseObject(text)
        if (j.str("format") != "luciverse.pevv.export") 0 else when (j.long("v")) { 2L -> 2; 1L -> 1; else -> 0 }
    } catch (_: Exception) {
        0
    }

    fun exportPortable(file: VaultFile, password: String, kdf: Kdf? = null, now: String = java.time.Instant.now().toString()): JsonObject {
        VaultFile.validate(file)
        val params = kdf ?: Crypto.newKdf()
        val kek = Crypto.passwordKek(password, params)
        val payload = buildJsonObject { put("kind", "vault"); put("file", file.json) }
        val sealed = Crypto.sealJson(kek, payload, Crypto.Aad.export(file.id))
        Bytes.wipe(kek)
        return buildJsonObject {
            put("format", "luciverse.pevv.export"); put("v", 2); put("id", file.id); put("created", now)
            put("kdf", params.toJson()); put("sealed", sealed.toJson())
        }
    }

    /** Opens a v2 export to a whole vault, or a v1 export to its items. */
    sealed class Opened {
        class Items(val entries: List<JsonObject>, val environments: List<String>) : Opened()
        class Vault(val file: VaultFile) : Opened()
    }

    fun openExport(text: String, password: String): Opened {
        val f = Json.parseObject(text)
        val v = f.long("v")
        if (f.str("format") != "luciverse.pevv.export" || (v != 1L && v != 2L)) throw IllegalArgumentException("not a PEVV export file")
        val id = f.str("id") ?: throw IllegalArgumentException("not a PEVV export file")
        val kek = Crypto.passwordKek(password, Kdf.from(f["kdf"]))
        try {
            val p = Crypto.openJson(kek, Sealed.from(f["sealed"]), Crypto.Aad.export(id)) as JsonObject
            if (v == 1L) {
                val entries = p.arr("entries")?.mapNotNull { it as? JsonObject } ?: throw IllegalArgumentException("export is empty")
                return Opened.Items(entries, p.strList("environments"))
            }
            val file = VaultFile(p.obj("file") ?: throw IllegalArgumentException("export is damaged"))
            VaultFile.validate(file)
            if (file.id != id) throw IllegalArgumentException("export is damaged")
            return Opened.Vault(file)
        } finally {
            Bytes.wipe(kek)
        }
    }
}
