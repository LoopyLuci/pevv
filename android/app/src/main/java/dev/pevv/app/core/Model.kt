package dev.pevv.app.core

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

const val VAULT_FORMAT = "luciverse.pevv"

val ENTRY_TYPES = listOf("login", "env", "note", "apikey", "card", "ssh", "identity", "passkey")

/** Order of the keys is the order `createVault` writes in the TypeScript client. Unknown keys are kept as they are. */
class VaultFile(val json: JsonObject) {
    val id: String get() = json.str("id") ?: ""
    val rev: Long get() = json.long("rev") ?: 0
    val created: Long get() = json.long("created") ?: 0
    val updated: Long get() = json.long("updated") ?: 0
    val kdf: Kdf get() = Kdf.from(json["kdf"])
    val slots: List<Slot> get() = (json.arr("slots") ?: JsonArray(emptyList())).mapNotNull { (it as? JsonObject)?.let(::Slot) }
    val entries: List<EntryRecord> get() = (json.arr("entries") ?: JsonArray(emptyList())).mapNotNull { (it as? JsonObject)?.let(::EntryRecord) }
    val meta: Sealed get() = Sealed.from(json["meta"])
    val totp: Sealed? get() = json["totp"]?.takeIf { it is JsonObject }?.let { Sealed.from(it) }
    val passkeys: JsonArray get() = json.arr("passkeys") ?: JsonArray(emptyList())
    val require: Require get() = Require.from(json.obj("require"))

    fun with(patch: Map<String, JsonElement?>) = VaultFile(json.with(patch))

    /** Serialised exactly as JSON.stringify does: compact, key order kept. This is what sync and QR carry. */
    fun toText(): String = Json.encode(json)

    companion object {
        fun parse(text: String): VaultFile {
            val f = VaultFile(Json.parseObject(text))
            validate(f)
            return f
        }

        /** The same checks as `validateFile`: unknown slot types are kept and ignored. */
        fun validate(f: VaultFile) {
            val j = f.json
            val ok = j.str("format") == VAULT_FORMAT && j.long("v") == 1L && j.str("id") != null && j["slots"] is JsonArray && j["entries"] is JsonArray
            if (!ok) throw IllegalArgumentException("not a PEVV vault file")
            for (s in j.arr("slots")!!) {
                val o = s as? JsonObject
                if (o == null || o.str("id") == null || o.str("type") == null) throw IllegalArgumentException("not a PEVV vault file")
                if (o.str("type") == "usb-key") {
                    val w = o.obj("wrapped")
                    if (o.str("salt") == null || o.str("name") == null || w?.str("iv") == null || w.str("ct") == null) {
                        throw IllegalArgumentException("not a PEVV vault file")
                    }
                }
            }
        }
    }
}

data class Require(val totp: Boolean, val passkey: Boolean, val usbKey: Boolean?) {
    fun toJson(): JsonObject = buildJsonObject {
        put("totp", totp)
        put("passkey", passkey)
        if (usbKey != null) put("usbKey", usbKey)
    }

    companion object {
        fun from(o: JsonObject?) = Require(o?.bool("totp") ?: false, o?.bool("passkey") ?: false, o?.bool("usbKey"))
    }
}

/** A key slot. Types this client does not know are carried unchanged. */
class Slot(val json: JsonObject) {
    val id: String get() = json.str("id") ?: ""
    val type: String get() = json.str("type") ?: ""
    val wrapped: Sealed get() = Sealed.from(json["wrapped"])
    val salt: String get() = json.str("salt") ?: ""
    val credId: String get() = json.str("credId") ?: ""
    val hash: String get() = json.str("hash") ?: ""
    val name: String get() = json.str("name") ?: ""

    companion object {
        fun password(id: String, wrapped: Sealed) = Slot(buildJsonObject {
            put("id", id); put("type", "password"); put("wrapped", wrapped.toJson())
        })

        fun prf(id: String, credId: String, salt: String, wrapped: Sealed) = Slot(buildJsonObject {
            put("id", id); put("type", "prf"); put("credId", credId); put("salt", salt); put("wrapped", wrapped.toJson())
        })

        fun recoveryCode(id: String, salt: String, hash: String, wrapped: Sealed) = Slot(buildJsonObject {
            put("id", id); put("type", "recovery-code"); put("salt", salt); put("hash", hash); put("wrapped", wrapped.toJson())
        })

        fun recoveryKey(id: String, salt: String, wrapped: Sealed) = Slot(buildJsonObject {
            put("id", id); put("type", "recovery-key"); put("salt", salt); put("wrapped", wrapped.toJson())
        })

        fun usbKey(id: String, name: String, salt: String, wrapped: Sealed) = Slot(buildJsonObject {
            put("id", id); put("type", "usb-key"); put("name", name); put("salt", salt); put("wrapped", wrapped.toJson())
        })
    }
}

class EntryRecord(val json: JsonObject) {
    val id: String get() = json.str("id") ?: ""
    val ver: Long get() = json.long("ver") ?: 0
    val sealed: Sealed get() = Sealed.from(json["sealed"])

    companion object {
        fun of(id: String, ver: Long, sealed: Sealed) = EntryRecord(buildJsonObject {
            put("id", id); put("ver", ver); put("sealed", sealed.toJson())
        })
    }
}

/** The sealed, decrypted index and settings. Unknown fields are kept. */
class VaultMeta(val json: JsonObject) {
    val environments: List<String> get() = json.strList("environments")
    val activeEnv: String get() = json.str("activeEnv") ?: "dev"
    val index: Map<String, Long> get() = json.obj("index")?.mapNotNull { (k, v) -> (v as? JsonPrimitive)?.content?.toLongOrNull()?.let { k to it } }?.toMap() ?: emptyMap()
    val require: Require get() = Require.from(json.obj("require"))
    val folders: List<String> get() = json.strList("folders")
    val devices: List<VaultDevice> get() = Devices.asDevices(json["devices"])
    val revokedDevices: List<String> get() = json.strList("revokedDevices")
    val usbKeys: List<UsbKeyGate> get() = (json.arr("usbKeys") ?: JsonArray(emptyList())).mapNotNull { e ->
        val o = e as? JsonObject ?: return@mapNotNull null
        val id = o.str("id") ?: return@mapNotNull null
        UsbKeyGate(id, o.str("name") ?: "", o.str("check") ?: "", o.long("added") ?: 0)
    }

    fun with(patch: Map<String, JsonElement?>) = VaultMeta(json.with(patch))

    companion object {
        /** `{ ...DEFAULT_META, ...sealedMeta }`: defaults first, then whatever the sealed meta has. */
        fun withDefaults(sealed: JsonObject): VaultMeta {
            val out = LinkedHashMap<String, JsonElement>(DEFAULT.json)
            out.putAll(sealed)
            return VaultMeta(JsonObject(out))
        }

        val DEFAULT = VaultMeta(buildJsonObject {
            put("environments", jstrs(listOf("dev", "prod")))
            put("activeEnv", "dev")
            put("grants", JsonObject(emptyMap()))
            put("index", JsonObject(emptyMap()))
            put("require", buildJsonObject { put("totp", false); put("passkey", false); put("usbKey", false) })
            put("usbKeys", JsonArray(emptyList()))
            put("totpLastStep", dev.pevv.app.core.jnull)
            put("folders", JsonArray(emptyList()))
            put("projectEnv", JsonObject(emptyMap()))
            put("devices", JsonArray(emptyList()))
            put("revokedDevices", JsonArray(emptyList()))
        })
    }
}

data class UsbKeyGate(val id: String, val name: String, val check: String, val added: Long) {
    fun toJson(): JsonObject = buildJsonObject {
        put("id", id); put("name", name); put("check", check); put("added", added)
    }
}

/** A decrypted item. `data` is the whole sealed object, so fields of newer clients survive an edit. */
class Entry(val id: String, val ver: Long, val data: JsonObject) {
    val type: String get() = data.str("type") ?: "note"
    val title: String get() = data.str("title") ?: ""
    fun s(key: String): String? = data.str(key)
    val tags: List<String> get() = data.strList("tags")
    val favorite: Boolean get() = data.bool("favorite") ?: false
    val folder: String? get() = data.str("folder")
    val updated: Long get() = data.long("updated") ?: 0
    val created: Long get() = data.long("created") ?: 0
    val site: String? get() = s("site")
    val username: String? get() = s("username")
    val password: String? get() = s("password")
    val notes: String? get() = s("notes")
    val history: List<JsonObject> get() = (data.arr("history") ?: JsonArray(emptyList())).mapNotNull { it as? JsonObject }

    val isPasskey: Boolean
        get() = type == "passkey" && s("rpId") != null && s("credentialId") != null && s("passkeyPrivateKey") != null

    /** Passkey items are never shown in the item list and never offered for login. */
    val isListable: Boolean get() = type != "passkey"
}

/** Fields shown and edited per item kind, in display order. `secret` fields are masked until revealed. */
data class FieldSpec(val key: String, val labelRes: String, val secret: Boolean = false, val multiline: Boolean = false)

object EntryKinds {
    val fields: Map<String, List<FieldSpec>> = mapOf(
        "login" to listOf(
            FieldSpec("site", "site"), FieldSpec("username", "username"), FieldSpec("password", "password", secret = true),
            FieldSpec("totp", "totp", secret = true),
        ),
        "env" to listOf(FieldSpec("name", "env_name"), FieldSpec("value", "env_value", secret = true, multiline = true), FieldSpec("env", "env_environment")),
        "note" to emptyList(),
        "apikey" to listOf(FieldSpec("service", "service"), FieldSpec("key", "api_key", secret = true)),
        "card" to listOf(
            FieldSpec("cardholder", "cardholder"), FieldSpec("number", "card_number", secret = true), FieldSpec("expiry", "expiry"),
            FieldSpec("cvv", "cvv", secret = true), FieldSpec("pin", "pin", secret = true),
        ),
        "ssh" to listOf(
            FieldSpec("privateKey", "ssh_private", secret = true, multiline = true), FieldSpec("publicKey", "ssh_public", multiline = true),
            FieldSpec("passphrase", "passphrase", secret = true),
        ),
        "identity" to listOf(
            FieldSpec("fullName", "full_name"), FieldSpec("email", "email"), FieldSpec("phone", "phone"), FieldSpec("address", "address", multiline = true),
        ),
        "passkey" to listOf(
            FieldSpec("rpId", "rp_id"), FieldSpec("rpName", "rp_name"), FieldSpec("userName", "username"), FieldSpec("userDisplayName", "display_name"),
            FieldSpec("credentialId", "credential_id"),
        ),
    )

    fun newData(type: String, now: Long = System.currentTimeMillis()): JsonObject = buildJsonObject {
        put("type", type)
        put("title", "")
        put("tags", JsonArray(emptyList()))
        put("favorite", false)
        put("created", now)
        put("updated", now)
        put("history", JsonArray(emptyList()))
    }

    val HISTORY_FIELDS = listOf("password", "value", "key", "totp", "username", "number", "cvv", "pin", "privateKey", "passphrase")
    const val HISTORY_MAX = 20

    /** Merge an edit and record the previous secret values in the item's own (encrypted) history. */
    fun applyEdit(prev: JsonObject, next: Map<String, JsonElement?>, now: Long = System.currentTimeMillis()): JsonObject {
        val history = ArrayList<JsonElement>()
        val oldHistory = prev.arr("history")?.toList() ?: emptyList()
        for (f in HISTORY_FIELDS) {
            if (!next.containsKey(f)) continue
            val before = prev.str(f)
            val after = (next[f] as? JsonPrimitive)?.content
            if (!before.isNullOrEmpty() && after != before) {
                history.add(0, buildJsonObject { put("at", now); put("field", f); put("value", before) })
            }
        }
        val all = history + oldHistory
        return prev.with(next + mapOf("updated" to jnum(now), "history" to JsonArray(all.take(HISTORY_MAX))))
    }

    fun subtitle(e: Entry): String {
        fun nz(vararg v: String?) = v.filter { !it.isNullOrEmpty() }.joinToString(" · ")
        return when (e.type) {
            "login" -> nz(e.username, e.site)
            "env" -> "${e.s("env") ?: "default"} · ${e.s("name") ?: ""}"
            "apikey" -> e.s("service") ?: ""
            "card" -> nz(e.s("number")?.takeIf { it.isNotEmpty() }?.let { "•••• " + it.filter(Char::isDigit).takeLast(4) }, e.s("expiry"))
            "ssh" -> (e.s("publicKey") ?: "").trim().split(Regex("\\s+")).filterIndexed { i, _ -> i != 1 }.joinToString(" ").take(60)
            "identity" -> nz(e.s("fullName"), e.s("email"))
            "passkey" -> nz(e.s("userName"), e.s("rpId"))
            else -> (e.notes ?: "").lineSequence().firstOrNull()?.take(60) ?: ""
        }
    }

    fun matchesQuery(e: Entry, q: String): Boolean {
        val s = q.trim().lowercase()
        if (s.isEmpty()) return true
        val hay = listOf("title", "site", "username", "name", "env", "service", "notes", "folder", "cardholder", "fullName", "email", "phone").mapNotNull { e.s(it) } + e.tags
        return hay.any { it.lowercase().contains(s) }
    }

    /** Groups of items that share the same secret (logins and API keys). */
    fun reuseGroups(entries: List<Entry>): Map<String, List<String>> {
        val by = LinkedHashMap<String, MutableList<String>>()
        for (e in entries) {
            val secret = when (e.type) { "login" -> e.password; "apikey" -> e.s("key"); else -> null }
            if (secret.isNullOrEmpty()) continue
            by.getOrPut(secret) { ArrayList() }.add(e.id)
        }
        val out = LinkedHashMap<String, List<String>>()
        for (ids in by.values) if (ids.size > 1) for (id in ids) out[id] = ids
        return out
    }
}
