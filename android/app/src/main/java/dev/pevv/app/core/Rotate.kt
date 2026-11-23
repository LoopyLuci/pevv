package dev.pevv.app.core

import dev.pevv.app.core.Bytes.b64
import dev.pevv.app.core.Bytes.utf8
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement

/**
 * Vault key rotation, the Kotlin twin of src/pevv/rotate.ts (same bytes for the same inputs; golden vectors in
 * tests/sync-scenarios/rotation.json). Items, the sealed meta and the authenticator secret are sealed directly under the
 * vault key, so all of them are re-sealed; every key slot is re-wrapped or removed. The file becomes `v: 2` with
 * `keyEpoch` >= 1, which clients that only know `v: 1` refuse cleanly.
 */
class RotatePlan(
    val password: String,
    val kdf: Kdf,
    val recoveryCodes: List<String> = emptyList(),
    val recoveryKey: String? = null,
    /** credId -> PRF output of that passkey, for every passkey slot to keep. */
    val prf: Map<String, ByteArray> = emptyMap(),
    /** Text of each `.pevvkey` file whose unlock slot is to be kept. */
    val usbKeyFiles: List<String> = emptyList(),
    val dropUnknown: Boolean = false,
)

class RotateOptions(
    val iv: IvFn? = null,
    val rng: (Int) -> ByteArray = { Bytes.random(it) },
    val newId: () -> String = { dev.pevv.app.core.newId() },
    val newKey: ByteArray? = null,
    val now: Long? = null,
)

data class DroppedSlot(val id: String, val type: String, val name: String? = null)

class RotateResult(val file: VaultFile, val session: Session, val dropped: List<DroppedSlot>)

object Rotate {
    private val KNOWN = setOf("password", "prf", "usb-key", "recovery-code", "recovery-key")

    fun rotateVaultKey(file: VaultFile, session: Session, plan: RotatePlan, opts: RotateOptions = RotateOptions()): RotateResult {
        VaultFile.validate(file)
        val unknown = file.slots.filter { it.type !in KNOWN }
        if (unknown.isNotEmpty() && !plan.dropUnknown) throw IllegalStateException("unknown-slot")

        val raw = opts.newKey ?: opts.rng(32)
        val next = Session(raw)
        fun seal(value: JsonElement, aad: String): Sealed = Crypto.sealJson(raw, value, aad, opts.iv?.invoke(aad, utf8(Json.encode(value))))
        fun wrap(kek: ByteArray, aad: String, slotId: String): Sealed =
            Crypto.wrapVaultKey(kek, raw, file.id, slotId, opts.iv?.invoke(aad, raw))

        val rev = file.rev + 1
        val entries = file.entries.map { r ->
            val a = Crypto.Aad.entry(file.id, r.id, r.ver)
            val data = Crypto.openJson(session.raw, r.sealed, a)
            EntryRecord.of(r.id, r.ver, seal(data, a))
        }
        val meta = VaultEngine.readMeta(file, session)
        val totp: JsonElement = file.totp?.let {
            val a = Crypto.Aad.totp(file.id)
            seal(Crypto.openJson(session.raw, it, a), a).toJson()
        } ?: jnull

        val dropped = ArrayList(unknown.map { DroppedSlot(it.id, it.type) })
        val slots = ArrayList<Slot>()
        val pwId = opts.newId()
        slots.add(Slot.password(pwId, wrap(Crypto.passwordKek(plan.password, plan.kdf), Crypto.Aad.slot(file.id, pwId), pwId)))

        val secrets = plan.usbKeyFiles.map { UsbKeyFile.parse(it).second }
        for (s in file.slots) {
            if (s.type == "prf") {
                val out = plan.prf[s.credId]
                var ok = false
                if (out != null) {
                    ok = try { Bytes.ctEqual(Crypto.unwrapVaultKey(VaultEngine.prfKek(out, s.salt), s.wrapped, file.id, s.id), session.raw) } catch (_: Exception) { false }
                }
                if (!ok || out == null) { dropped.add(DroppedSlot(s.id, s.type)); continue }
                val id = opts.newId()
                val salt = b64(opts.rng(32))
                slots.add(Slot.prf(id, s.credId, salt, wrap(VaultEngine.prfKek(out, salt), Crypto.Aad.slot(file.id, id), id)))
            } else if (s.type == "usb-key") {
                var secret: ByteArray? = null
                for (c in secrets) {
                    val same = try { Bytes.ctEqual(Crypto.unwrapVaultKey(VaultEngine.usbKek(c, s.salt), s.wrapped, file.id, s.id), session.raw) } catch (_: Exception) { false }
                    if (same) { secret = c; break }
                }
                if (secret == null) { dropped.add(DroppedSlot(s.id, s.type, s.name)); continue }
                val id = opts.newId()
                val salt = b64(opts.rng(32))
                slots.add(Slot.usbKey(id, s.name, salt, wrap(VaultEngine.usbKek(secret, salt), Crypto.Aad.slot(file.id, id), id)))
            }
        }
        for (code in plan.recoveryCodes) {
            val id = opts.newId()
            val salt = b64(opts.rng(16))
            slots.add(Slot.recoveryCode(id, salt, Recovery.codeHash(code, salt), wrap(Recovery.codeKek(code, salt), Crypto.Aad.slot(file.id, id), id)))
        }
        if (plan.recoveryKey != null) {
            val id = opts.newId()
            val salt = b64(opts.rng(16))
            slots.add(Slot.recoveryKey(id, salt, wrap(Recovery.recoveryKeyKek(plan.recoveryKey, salt), Crypto.Aad.slot(file.id, id), id)))
        }
        for (s in file.slots) {
            if ((s.type == "recovery-code" && plan.recoveryCodes.isEmpty()) || (s.type == "recovery-key" && plan.recoveryKey == null)) dropped.add(DroppedSlot(s.id, s.type))
        }

        val out = file.with(
            linkedMapOf(
                "v" to jnum(2),
                "rev" to jnum(rev),
                "updated" to jnum(opts.now ?: System.currentTimeMillis()),
                "kdf" to plan.kdf.toJson(),
                "slots" to JsonArray(slots.map { it.json }),
                "totp" to totp,
                "meta" to seal(meta.json, Crypto.Aad.meta(file.id, rev)).toJson(),
                "entries" to JsonArray(entries.map { it.json }),
                "keyEpoch" to jnum(file.keyEpoch + 1),
            ),
        )
        return RotateResult(out, next, dropped)
    }
}
