package dev.pevv.app.core

import dev.pevv.app.core.Bytes.utf8
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/** Deterministic IV source for golden tests. Production leaves it null (random 96-bit IV per seal). */
typealias IvFn = (aad: String, plain: ByteArray) -> ByteArray

data class MergeOptions(val iv: IvFn? = null, val now: Long? = null, val writer: String? = null)

data class ConflictNote(val id: String, val title: String, val kind: String, val kept: String)

/** kind: same | kept-local | took-remote | merged | key-rotated | rejected. reason (when rejected): other-vault | stale-key | key-mismatch | revoked-writer. */
data class MergeOutcome(val kind: String, val file: VaultFile?, val conflicts: List<ConflictNote>, val reason: String? = null)

/**
 * Sync merge, the Kotlin twin of src/pevv/merge.ts. Same rules, same tie-breaks, same key order, so that both clients
 * write byte-identical merged files (tests/sync-scenarios). The rules in prose are in docs/SYNC.md.
 */
object Merge {
    const val CONFLICT_KEEP = 5

    /** JSON with sorted keys: the same text in every client. A null (absent) value stands for `undefined`. */
    fun canon(v: JsonElement?): String = when (v) {
        null -> "undefined"
        is JsonObject -> "{" + v.keys.sorted().joinToString(",") { k -> Json.encode(JsonPrimitive(k)) + ":" + canon(v[k]) } + "}"
        is JsonArray -> "[" + v.joinToString(",") { canon(it) } + "]"
        else -> Json.encode(v)
    }

    private fun num(v: JsonElement?): Long = (v as? JsonPrimitive)?.takeIf { !it.isString && it !is JsonNull }?.let { it.content.toLongOrNull() ?: it.content.toDoubleOrNull()?.toLong() } ?: 0
    private fun arr(v: JsonElement?): List<JsonElement> = (v as? JsonArray)?.toList() ?: emptyList()
    private fun recEq(x: EntryRecord, y: EntryRecord) = x.ver == y.ver && x.sealed.iv == y.sealed.iv && x.sealed.ct == y.sealed.ct
    private fun cmpText(x: String, y: String) = x.compareTo(y).coerceIn(-1, 1)

    private fun sealWith(s: Session, value: JsonElement, aad: String, o: MergeOptions): Sealed =
        Crypto.sealJson(s.raw, value, aad, o.iv?.invoke(aad, utf8(Json.encode(value))))

    /** Three-way pick of one value. null means absent. Without a base, a present value beats an absent one. */
    private fun pick(hasBase: Boolean, base: JsonElement?, a: JsonElement?, b: JsonElement?): JsonElement? {
        val ca = canon(a)
        val cb = canon(b)
        if (ca == cb) return a
        if (hasBase) {
            val c0 = canon(base)
            if (c0 == ca) return b
            if (c0 == cb) return a
        }
        return a ?: b
    }

    /** Ordered union of two lists; with a base, an item one side removed stays removed. */
    private fun mergeList(hasBase: Boolean, base: JsonElement?, a: JsonElement?, b: JsonElement?): List<JsonElement> {
        val la = arr(a)
        val lb = arr(b)
        val out = ArrayList(la)
        val have = la.map { canon(it) }.toHashSet()
        for (x in lb) if (canon(x) !in have) out.add(x)
        if (!hasBase) return out
        val inBase = arr(base).map { canon(it) }.toHashSet()
        val inB = lb.map { canon(it) }.toHashSet()
        return out.filter { x ->
            val c = canon(x)
            !(c in inBase && (c !in have || c !in inB))
        }
    }

    private fun mergeMap(hasBase: Boolean, base: JsonElement?, a: JsonElement?, b: JsonElement?, each: (Boolean, JsonElement?, JsonElement?, JsonElement?) -> JsonElement?): JsonObject {
        val oa = a as? JsonObject ?: JsonObject(emptyMap())
        val ob = b as? JsonObject ?: JsonObject(emptyMap())
        val o0 = base as? JsonObject ?: JsonObject(emptyMap())
        val out = LinkedHashMap<String, JsonElement>()
        for (k in oa.keys + ob.keys.filter { it !in oa }) {
            val v = each(hasBase, o0[k], oa[k], ob[k])
            if (v != null) out[k] = v
        }
        return JsonObject(out)
    }

    private fun mergeById(hasBase: Boolean, base: JsonElement?, a: JsonElement?, b: JsonElement?): JsonElement? {
        val lists = listOf(arr(a), arr(b), arr(base))
        if (!lists.all { l -> l.all { (it as? JsonObject)?.str("id") != null } }) return pick(hasBase, base, a, b)
        fun idx(l: List<JsonElement>) = LinkedHashMap<String, JsonElement>().also { m -> l.forEach { m[(it as JsonObject).str("id")!!] = it } }
        val (ma, mb, m0) = lists.map { idx(it) }
        val out = ArrayList<JsonElement>()
        for (id in ma.keys + mb.keys.filter { it !in ma }) pick(hasBase, m0[id], ma[id], mb[id])?.let { out.add(it) }
        return JsonArray(out)
    }

    private fun mergeMeta(hasBase: Boolean, base: VaultMeta?, a: VaultMeta, b: VaultMeta): JsonObject {
        val A = a.json
        val B = b.json
        val B0 = base?.json ?: JsonObject(emptyMap())
        val roster = Devices.mergeRoster(RosterSlice(a.devices, a.revokedDevices), RosterSlice(b.devices, b.revokedDevices))
        val out = LinkedHashMap<String, JsonElement>()
        for (k in A.keys + B.keys.filter { it !in A }) {
            val v: JsonElement? = when (k) {
                "environments", "folders" -> JsonArray(mergeList(hasBase, B0[k], A[k], B[k]))
                "grants" -> mergeMap(hasBase, B0[k], A[k], B[k]) { hb, x, y, z -> mergeList(hb, x, y, z).let { l -> if (l.isEmpty()) null else JsonArray(l) } }
                "projectEnv", "require" -> mergeMap(hasBase, B0[k], A[k], B[k]) { hb, x, y, z -> pick(hb, x, y, z) }
                "usbKeys" -> mergeById(hasBase, B0[k], A[k], B[k])
                "devices" -> Devices.devicesJson(roster.devices)
                "revokedDevices" -> jstrs(roster.revokedDevices)
                "trustEpoch" -> {
                    val x = A[k]
                    val y = B[k]
                    fun isNum(e: JsonElement?) = e is JsonPrimitive && !e.isString && e !is JsonNull
                    if (isNum(x) && isNum(y)) jnum(maxOf(num(x), num(y))) else pick(hasBase, B0[k], x, y)
                }
                "totpLastStep" -> {
                    val x = A[k]
                    val y = B[k]
                    fun isNum(e: JsonElement?) = e is JsonPrimitive && !e.isString && e !is JsonNull
                    if (isNum(x) && isNum(y)) jnum(maxOf(num(x), num(y))) else pick(hasBase, B0[k], x, y)
                }
                else -> pick(hasBase, B0[k], A[k], B[k])
            }
            if (v != null) out[k] = v
        }
        return JsonObject(out)
    }

    private val KNOWN_TOP = setOf("format", "v", "id", "created", "updated", "rev", "keyEpoch", "kdf", "slots", "passkeys", "require", "totp", "meta", "entries")
    private val CRED = listOf("kdf", "slots", "passkeys", "totp")

    private fun credBlock(f: VaultFile): JsonObject {
        val m = LinkedHashMap<String, JsonElement>()
        for (k in CRED) f.json[k]?.let { m[k] = it }
        return JsonObject(m)
    }

    private fun extras(f: VaultFile): JsonObject = JsonObject(f.json.filterKeys { it !in KNOWN_TOP })

    private fun contentKey(entries: List<EntryRecord>, json: JsonObject, meta: JsonObject): String {
        val m = meta.with("lastWriter" to null)
        val recs = entries.sortedBy { it.id }
        val cred = JsonObject(CRED.mapNotNull { k -> json[k]?.let { k to it } }.toMap())
        return canon(buildJsonObject {
            put("entries", JsonArray(recs.map { it.json }))
            put("meta", m)
            put("cred", cred)
            put("extras", JsonObject(json.filterKeys { it !in KNOWN_TOP }))
        })
    }

    private fun openEntry(s: Session, f: VaultFile, r: EntryRecord): JsonObject? =
        try { Crypto.openJson(s.raw, r.sealed, Crypto.Aad.entry(f.id, r.id, r.ver)) as? JsonObject } catch (_: Exception) { null }

    private fun withoutConflicts(d: JsonObject): JsonObject = d.with("conflicts" to null)

    private fun snapshot(data: JsonObject, ver: Long): JsonObject = buildJsonObject {
        put("at", num(data["updated"])); put("ver", ver); put("data", withoutConflicts(data))
    }

    private fun keepConflicts(winner: JsonObject, loser: JsonObject, loserSnap: JsonObject): JsonArray {
        val all = listOf<JsonElement>(loserSnap) + arr(winner["conflicts"]) + arr(loser["conflicts"])
        val seen = HashSet<String>()
        val uniq = all.filter { seen.add(canon(it)) }
        val sorted = uniq.sortedWith { x, y ->
            val d = num((y as? JsonObject)?.get("at")) - num((x as? JsonObject)?.get("at"))
            if (d != 0L) d.coerceIn(-1, 1).toInt() else cmpText(canon(x), canon(y))
        }
        return JsonArray(sorted.take(CONFLICT_KEEP))
    }

    private fun none(kind: String, file: VaultFile?, conflicts: List<ConflictNote> = emptyList(), reason: String? = null) = MergeOutcome(kind, file, conflicts, reason)

    /** Fold `remote` into `local`. `base` is the copy last known to be in sync with the server (null when unknown). */
    fun mergeVaults(session: Session, base0: VaultFile?, local: VaultFile, remote: VaultFile, opts: MergeOptions = MergeOptions()): MergeOutcome {
        var base = base0
        VaultFile.validate(local)
        VaultFile.validate(remote)
        if (local.id != remote.id) return none("rejected", null, reason = "other-vault")
        val le = local.keyEpoch
        val re = remote.keyEpoch
        if (re < le) return none("rejected", null, reason = "stale-key")
        if (re > le) return none("key-rotated", remote)
        if (canon(local.json) == canon(remote.json)) return none("same", local)
        if (base != null && (base.id != local.id || base.keyEpoch != le || remote.rev <= base.rev)) base = null

        val rmeta = try { VaultEngine.readMeta(remote, session) } catch (_: Exception) { return none("rejected", null, reason = "key-mismatch") }
        val lmeta = VaultEngine.readMeta(local, session)
        var bmeta: VaultMeta? = null
        if (base != null) {
            try { bmeta = VaultEngine.readMeta(base, session) } catch (_: Exception) { base = null }
        }
        val revoked = (lmeta.revokedDevices + (bmeta?.revokedDevices ?: emptyList())).toSet()
        val writer = rmeta.json.str("lastWriter")
        if (writer != null && writer in revoked) return none("rejected", null, reason = "revoked-writer")

        fun same(x: VaultFile, y: VaultFile) = canon(x.json) == canon(y.json)
        if (base != null && same(local, base)) return none("took-remote", remote)
        if (base != null && same(remote, base)) return none("kept-local", local)

        // Orient the pair by a total order so that the result does not depend on which side is "mine".
        var order = local.rev - remote.rev
        if (order == 0L) order = local.updated - remote.updated
        if (order == 0L) order = cmpText(canon(local.json), canon(remote.json)).toLong()
        val localPrimary = order >= 0
        val P = if (localPrimary) local else remote
        val S = if (localPrimary) remote else local
        val pmeta = if (localPrimary) lmeta else rmeta
        val smeta = if (localPrimary) rmeta else lmeta
        fun side(primary: Boolean) = if (primary == localPrimary) "local" else "remote"
        val hasBase = base != null

        /* ---- items ---- */
        val baseRecs = (base?.entries ?: emptyList()).associateBy { it.id }
        val pRecs = LinkedHashMap<String, EntryRecord>().also { m -> P.entries.forEach { m[it.id] = it } }
        val sRecs = LinkedHashMap<String, EntryRecord>().also { m -> S.entries.forEach { m[it.id] = it } }
        val ids = pRecs.keys + sRecs.keys.filter { it !in pRecs }
        val conflicts = ArrayList<ConflictNote>()
        val merged = ArrayList<EntryRecord>()

        for (id in ids) {
            val rp = pRecs[id]
            val rs = sRecs[id]
            val r0 = baseRecs[id]
            if (rp != null && rs != null) {
                if (recEq(rp, rs)) { merged.add(rp); continue }
                if (hasBase && r0 != null && recEq(rp, r0)) { merged.add(rs); continue }
                if (hasBase && r0 != null && recEq(rs, r0)) { merged.add(rp); continue }
                val dp = openEntry(session, P, rp)
                val ds = openEntry(session, S, rs)
                if (dp == null || ds == null) { merged.add(if (dp != null) rp else if (ds != null) rs else rp); continue }
                if (canon(withoutConflicts(dp)) == canon(withoutConflicts(ds))) {
                    merged.add(if (rp.ver > rs.ver || (rp.ver == rs.ver && arr(dp["conflicts"]).size >= arr(ds["conflicts"]).size)) rp else rs)
                    continue
                }
                fun held(d: JsonObject, other: JsonObject) = arr(d["conflicts"]).any { c -> canon((c as? JsonObject)?.get("data")) == canon(withoutConflicts(other)) }
                if (held(ds, dp)) { merged.add(rs); continue }
                if (held(dp, ds)) { merged.add(rp); continue }
                if (!hasBase) {
                    val hi = if (rp.ver > rs.ver) rp else if (rs.ver > rp.ver) rs else null
                    if (hi != null) {
                        val dh = if (hi === rp) dp else ds
                        val dl = if (hi === rp) ds else dp
                        if (num(dh["updated"]) >= num(dl["updated"])) { merged.add(hi); continue }
                    }
                }
                var c = num(dp["updated"]) - num(ds["updated"])
                if (c == 0L) c = rp.ver - rs.ver
                if (c == 0L) c = cmpText(canon(withoutConflicts(dp)), canon(withoutConflicts(ds))).toLong()
                val pWins = c >= 0
                val wd = if (pWins) dp else ds
                val ld = if (pWins) ds else dp
                val lv = if (pWins) rs.ver else rp.ver
                val ver = maxOf(rp.ver, rs.ver) + 1
                val data = wd.with("conflicts" to keepConflicts(wd, ld, snapshot(ld, lv)))
                merged.add(EntryRecord.of(id, ver, sealWith(session, data, Crypto.Aad.entry(local.id, id, ver), opts)))
                conflicts.add(ConflictNote(id, wd.str("title") ?: "", "edited-both", side(pWins)))
                continue
            }
            val mine = (rp ?: rs)!!
            val mineIsP = rp != null
            if (hasBase && r0 != null) {
                // It existed at the last sync and the other side no longer has it.
                if (recEq(mine, r0)) continue
                merged.add(mine)
                val title = openEntry(session, if (mineIsP) P else S, mine)?.str("title") ?: ""
                conflicts.add(ConflictNote(id, title, "deleted-vs-edited", side(mineIsP)))
                continue
            }
            merged.add(mine)
        }

        /* ---- meta, credentials, unknown fields ---- */
        val meta0 = mergeMeta(hasBase, if (hasBase) bmeta else null, pmeta, smeta)
        val metaPatch = LinkedHashMap<String, JsonElement?>()
        metaPatch["index"] = JsonObject(LinkedHashMap<String, JsonElement>().also { m -> merged.forEach { m[it.id] = jnum(it.ver) } })
        if (opts.writer != null) metaPatch["lastWriter"] = jstr(opts.writer)
        val meta = meta0.with(metaPatch)
        val credP = credBlock(P)
        val credS = credBlock(S)
        val credBase = if (base != null) credBlock(base) else null
        val cred = pick(hasBase, credBase, credP, credS) as JsonObject

        val out = LinkedHashMap<String, JsonElement>(P.json)
        for ((k, v) in S.json) if (k !in out) out[k] = v
        val rev = maxOf(local.rev, remote.rev) + 1
        out["created"] = jnum(minOf(local.created, remote.created))
        out["updated"] = jnum(opts.now ?: System.currentTimeMillis())
        out["rev"] = jnum(rev)
        for (k in CRED) { val v = cred[k]; if (v != null) out[k] = v else out.remove(k) }
        out["require"] = JsonObject((meta["require"] as? JsonObject) ?: JsonObject(emptyMap()))
        out["entries"] = JsonArray(merged.map { it.json })

        val key = contentKey(merged, JsonObject(out), meta)
        if (key == contentKey(local.entries, local.json, lmeta.json) && local.rev > remote.rev) return none("kept-local", local, conflicts)
        if (key == contentKey(remote.entries, remote.json, rmeta.json) && remote.rev > local.rev) return none("took-remote", remote, conflicts)
        out["meta"] = sealWith(session, meta, Crypto.Aad.meta(local.id, rev), opts).toJson()
        return none("merged", VaultFile(JsonObject(out)), conflicts)
    }

    /** Restore the items of an older copy as a new revision on top of the current one (roster, revocations and key slots stay as they are). */
    class Restored(val file: VaultFile, val restored: Int, val removed: Int)

    fun restoreRevision(session: Session, current: VaultFile, old: VaultFile, opts: MergeOptions = MergeOptions()): Restored {
        VaultFile.validate(current)
        VaultFile.validate(old)
        if (old.id != current.id) throw IllegalStateException("other-vault")
        if (old.keyEpoch != current.keyEpoch) throw IllegalStateException("stale-key")
        val cur = current.entries.associateBy { it.id }
        val oldIds = old.entries.map { it.id }.toSet()
        val rev = current.rev + 1
        val entries = ArrayList<EntryRecord>()
        var restored = 0
        for (r in old.entries) {
            val c = cur[r.id]
            if (c != null && recEq(c, r)) { entries.add(c); continue }
            val data = openEntry(session, old, r) ?: throw IllegalStateException("key-mismatch")
            val ver = maxOf(c?.ver ?: 0, r.ver) + 1
            entries.add(EntryRecord.of(r.id, ver, sealWith(session, data, Crypto.Aad.entry(current.id, r.id, ver), opts)))
            restored++
        }
        val removed = current.entries.count { it.id !in oldIds }
        val patch = LinkedHashMap<String, JsonElement?>()
        patch["index"] = JsonObject(LinkedHashMap<String, JsonElement>().also { m -> entries.forEach { m[it.id] = jnum(it.ver) } })
        if (opts.writer != null) patch["lastWriter"] = jstr(opts.writer)
        val meta = VaultEngine.readMeta(current, session).json.with(patch)
        val out = current.with(
            mapOf(
                "rev" to jnum(rev), "updated" to jnum(opts.now ?: System.currentTimeMillis()),
                "entries" to JsonArray(entries.map { it.json }), "meta" to sealWith(session, meta, Crypto.Aad.meta(current.id, rev), opts).toJson(),
            ),
        )
        return Restored(out, restored, removed)
    }
}
