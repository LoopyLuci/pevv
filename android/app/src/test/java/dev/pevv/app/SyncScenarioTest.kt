package dev.pevv.app

import dev.pevv.app.core.Bytes
import dev.pevv.app.core.Bytes.b64
import dev.pevv.app.core.Bytes.utf8
import dev.pevv.app.core.Crypto
import dev.pevv.app.core.DecryptError
import dev.pevv.app.core.EntryRecord
import dev.pevv.app.core.IvFn
import dev.pevv.app.core.Json
import dev.pevv.app.core.Kdf
import dev.pevv.app.core.Merge
import dev.pevv.app.core.MergeOptions
import dev.pevv.app.core.MergeOutcome
import dev.pevv.app.core.RotateOptions
import dev.pevv.app.core.RotatePlan
import dev.pevv.app.core.Session
import dev.pevv.app.core.Rotate
import dev.pevv.app.core.VaultEngine
import dev.pevv.app.core.VaultFile
import dev.pevv.app.core.VaultMeta
import dev.pevv.app.core.arr
import dev.pevv.app.core.jnull
import dev.pevv.app.core.jnum
import dev.pevv.app.core.jstr
import dev.pevv.app.core.jstrs
import dev.pevv.app.core.long
import dev.pevv.app.core.obj
import dev.pevv.app.core.str
import dev.pevv.app.core.strList
import dev.pevv.app.core.with
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.File

/**
 * The Kotlin half of the cross-client sync scenarios. the .json files in tests/sync-scenarios are the shared spec (the TypeScript half is
 * tests/unit/pevv.sync-scenarios.test.ts); both must produce byte-identical files, which are checked against the files in golden/
 * (written by the TypeScript test). A mismatch here means the two merge implementations have diverged.
 */
class SyncScenarioTest {
    private val dir = File(System.getProperty("pevv.scenarios") ?: error("pevv.scenarios is not set"))
    private val keyHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

    private class Dev(var raw: ByteArray, var file: VaultFile? = null, var base: VaultFile? = null)

    private fun ivFor(key: ByteArray): IvFn = { aad, plain -> Crypto.hmacSha256(key, utf8(aad) + byteArrayOf(0) + plain).copyOf(12) }

    private fun JsonObject.o(k: String) = this[k] as JsonObject
    private fun JsonObject.s(k: String) = str(k)!!
    private fun JsonObject.l(k: String) = long(k)!!

    private class Result(val outcomes: List<String>, val files: Map<String, String>)

    private fun view(d: Dev): Triple<Map<String, JsonObject>, JsonObject, VaultFile> {
        val f = d.file!!
        val items = LinkedHashMap<String, JsonObject>()
        for (r in f.entries) {
            val data = Crypto.openJson(d.raw, r.sealed, Crypto.Aad.entry(f.id, r.id, r.ver))
            items[r.id] = buildJsonObject { put("ver", r.ver); put("data", data) }
        }
        return Triple(items, VaultEngine.readMeta(f, Session(d.raw)).json, f)
    }

    private fun run(sc: JsonObject): Result {
        val vaultId = sc.s("vaultId")
        val devs = LinkedHashMap<String, Dev>()
        val snaps = HashMap<String, VaultFile>()
        val outcomes = ArrayList<String>()
        fun dev(name: String) = devs.getOrPut(name) { Dev(Bytes.unhex(keyHex)) }
        fun opts(d: Dev, now: Long?, writer: String?) = MergeOptions(ivFor(d.raw), now, writer)
        fun seal(d: Dev, v: JsonElement, aad: String) = Crypto.sealJson(d.raw, v, aad, ivFor(d.raw)(aad, utf8(Json.encode(v))))

        fun commit(d: Dev, name: String, now: Long, change: (JsonObject) -> JsonObject, patch: (VaultFile, List<EntryRecord>) -> List<EntryRecord>?) {
            val f = d.file!!
            var m = change(VaultEngine.readMeta(f, Session(d.raw)).json)
            val rev = f.rev + 1
            m = m.with("lastWriter" to jstr(name))
            var next = f.with(mapOf("rev" to jnum(rev), "updated" to jnum(now)))
            val entries = patch(f, f.entries) ?: f.entries
            next = next.with(mapOf("entries" to JsonArray(entries.map { it.json })))
            m = m.with("index" to JsonObject(entries.associate { it.id to jnum(it.ver) }.let { LinkedHashMap(it) }))
            next = next.with(mapOf("require" to (m["require"] as JsonObject), "meta" to seal(d, m, Crypto.Aad.meta(f.id, rev)).toJson()))
            d.file = next
        }

        for (stEl in sc.arr("steps")!!) {
            val st = stEl as JsonObject
            val name = st.str("device") ?: ""
            when (val op = st.s("op")) {
                "create" -> {
                    val d = dev(name)
                    val items = st.arr("items")!!.map { it as JsonObject }
                    val entries = items.map { EntryRecord.of(it.s("id"), 1, seal(d, it.o("data"), Crypto.Aad.entry(vaultId, it.s("id"), 1))) }
                    var meta = VaultMeta.DEFAULT.json
                    st.obj("meta")?.let { meta = meta.with(it.toMap()) }
                    meta = meta.with("index" to JsonObject(LinkedHashMap<String, JsonElement>().also { m -> entries.forEach { m[it.id] = jnum(it.ver) } }), "lastWriter" to jstr(name))
                    val kek = ByteArray(32) { 0xaa.toByte() }
                    val slotAad = Crypto.Aad.slot(vaultId, "s-pw")
                    val pwSlot = buildJsonObject {
                        put("id", "s-pw"); put("type", "password")
                        put("wrapped", Crypto.wrapVaultKey(kek, d.raw, vaultId, "s-pw", ivFor(d.raw)(slotAad, d.raw)).toJson())
                    }
                    val at = st.l("at")
                    var file = JsonObject(
                        linkedMapOf(
                            "format" to jstr("luciverse.pevv"), "v" to jnum(1), "id" to jstr(vaultId), "created" to jnum(at), "updated" to jnum(at), "rev" to jnum(1),
                            "kdf" to buildJsonObject { put("alg", "pbkdf2-sha256"); put("iter", 600000); put("salt", b64(ByteArray(16) { 7 })) },
                            "slots" to JsonArray(listOf<JsonElement>(pwSlot) + (st.arr("slots")?.toList() ?: emptyList())),
                            "passkeys" to JsonArray(emptyList()),
                            "require" to (meta["require"] as JsonObject),
                            "totp" to jnull,
                            "meta" to seal(d, meta, Crypto.Aad.meta(vaultId, 1)).toJson(),
                            "entries" to JsonArray(entries.map { it.json }),
                        ),
                    )
                    st.obj("top")?.let { file = file.with(it.toMap()) }
                    d.file = VaultFile(file)
                    d.base = d.file
                }
                "copy" -> {
                    val from = dev(st.s("from"))
                    val to = dev(st.s("to"))
                    to.file = from.file; to.base = from.file; to.raw = from.raw
                }
                "edit", "add" -> {
                    val d = dev(name)
                    val id = st.s("id")
                    commit(d, name, st.l("at"), { it }) { f, entries ->
                        val prev = entries.firstOrNull { it.id == id }
                        val data: JsonObject = if (op == "add") st.o("data") else {
                            var x = Crypto.openJson(d.raw, prev!!.sealed, Crypto.Aad.entry(f.id, id, prev.ver)) as JsonObject
                            for ((k, v) in st.o("set")) x = if (v is JsonNull) x.with(k to null) else x.with(k to v)
                            x.with("updated" to jnum(st.l("at")))
                        }
                        val ver = (prev?.ver ?: 0) + 1
                        val rec = EntryRecord.of(id, ver, seal(d, data, Crypto.Aad.entry(f.id, id, ver)))
                        if (prev != null) entries.map { if (it.id == id) rec else it } else entries + rec
                    }
                }
                "delete" -> commit(dev(name), name, st.l("at"), { it }) { _, entries -> entries.filter { it.id != st.s("id") } }
                "meta" -> commit(dev(name), name, st.l("at"), { m -> m.with(st.o("patch").toMap()) }) { _, _ -> null }
                "revoke" -> commit(dev(name), name, st.l("at"), { m ->
                    val target = st.s("target")
                    val devices = JsonArray((m.arr("devices")?.toList() ?: emptyList()).filter { (it as? JsonObject)?.str("id") != target })
                    m.with("revokedDevices" to jstrs(m.strList("revokedDevices") + target), "devices" to devices)
                }) { _, _ -> null }
                "top" -> {
                    val d = dev(name)
                    d.file = VaultFile(d.file!!.json.with(st.o("patch").toMap()))
                }
                "snapshot" -> snaps[st.s("name")] = dev(name).file!!
                "restore" -> {
                    val d = dev(name)
                    val r = Merge.restoreRevision(Session(d.raw), d.file!!, snaps[st.s("name")]!!, opts(d, st.l("at"), name))
                    d.file = r.file
                    outcomes.add("restore:${r.restored}:${r.removed}")
                }
                "rotate" -> {
                    val d = dev(name)
                    val newKey = Bytes.unhex(st.s("newKeyHex"))
                    var i = 0
                    val r = Rotate.rotateVaultKey(
                        d.file!!, Session(d.raw),
                        RotatePlan("pw", Kdf.Pbkdf2(600000, b64(ByteArray(16) { 9 })), dropUnknown = true),
                        RotateOptions(iv = ivFor(newKey), rng = { n -> ByteArray(n) { 0x33 } }, newId = { "rot-${i++}" }, newKey = newKey, now = st.l("at")),
                    )
                    d.file = r.file; d.base = r.file; d.raw = newKey
                }
                "sync" -> {
                    val d = dev(name)
                    val other = devs[st.s("with")]!!
                    val useBase = st["base"]?.let { (it as? JsonPrimitive)?.content != "false" } ?: true
                    val out: MergeOutcome = Merge.mergeVaults(Session(d.raw), if (useBase) d.base else null, d.file!!, other.file!!, opts(d, st.l("now"), name))
                    val cs = out.conflicts.map { "${it.id}/${it.kind}/${it.kept}" }.sorted()
                    outcomes.add(out.kind + (out.reason?.let { ":$it" } ?: "") + if (cs.isNotEmpty()) ":" + cs.joinToString(",") else "")
                    st.obj("expect")?.let { e ->
                        assertEquals("${sc.s("name")} sync $name", e.s("kind"), out.kind)
                        e.str("reason")?.let { assertEquals(it, out.reason) }
                        e.arr("conflicts")?.let { c -> assertEquals(c.map { (it as JsonPrimitive).content }.sorted(), out.conflicts.map { "${it.id}/${it.kind}" }.sorted()) }
                    }
                    if (out.kind == "merged" || out.kind == "took-remote" || out.kind == "key-rotated") { d.file = out.file; d.base = out.file }
                }
                else -> fail("unknown op $op")
            }
        }

        val name = sc.s("name")
        for (aEl in sc.arr("asserts")!!) {
            val a = aEl as JsonObject
            val t = a.s("t")
            if (t == "same") {
                val vs = a.arr("devices")!!.map { n ->
                    val (items, meta, _) = view(devs[(n as JsonPrimitive).content]!!)
                    Merge.canon(buildJsonObject { put("items", JsonObject(items)); put("meta", meta.with("lastWriter" to null)) })
                }
                vs.forEach { assertEquals(name, vs[0], it) }
                continue
            }
            val (items, meta, f) = view(devs[a.s("device")]!!)
            when (t) {
                "field" -> assertEquals("$name ${a.s("id")}.${a.s("field")}", Merge.canon(a["equals"]), Merge.canon(items[a.s("id")]?.o("data")?.get(a.s("field"))))
                "absent" -> assertTrue(name, items[a.s("id")] == null)
                "count" -> assertEquals(name, a.l("n").toInt(), items.size)
                "conflicts" -> assertEquals(name, a.l("n").toInt(), items[a.s("id")]!!.o("data").arr("conflicts")?.size ?: 0)
                "meta" -> assertEquals(name, Merge.canon(a["equals"]), Merge.canon(meta[a.s("key")]))
                "top" -> assertEquals(name, Merge.canon(a["equals"]), Merge.canon(f.json[a.s("key")]))
                "slotTypes" -> assertEquals(name, a.strList("equals"), f.slots.map { it.type })
                "rev" -> assertEquals(name, a.l("equals"), f.rev)
                else -> fail("unknown assert $t")
            }
        }
        return Result(outcomes, devs.filter { it.value.file != null }.mapValues { it.value.file!!.toText() })
    }

    @Test
    fun scenariosMatchTheGoldenFilesByteForByte() {
        val files = dir.listFiles { f -> f.isFile && f.name.endsWith(".json") }!!.sortedBy { it.name }
        assertTrue("expected at least 8 scenarios", files.size >= 8)
        for (f in files) {
            val sc = Json.parseObject(f.readText())
            val got = run(sc)
            val golden = Json.parseObject(File(dir, "golden/${f.name}").readText())
            assertEquals("${f.name} outcomes", golden.arr("outcomes")!!.map { (it as JsonPrimitive).content }, got.outcomes)
            val gf = golden.o("files")
            assertEquals("${f.name} devices", gf.keys, got.files.keys)
            for ((n, text) in got.files) assertEquals("${f.name} device $n must be byte-identical to the TypeScript client", gf.s(n), text)
        }
    }

    @Test
    fun keyRotationMatchesTheGoldenVector() {
        val v = Json.parseObject(File(dir, "vectors/rotation.json").readText())
        val plan = v.o("plan")
        val newKey = Bytes.unhex(v.s("newKeyHex"))
        val oldKey = Bytes.unhex(v.s("vaultKeyHex"))
        val input = VaultFile.parse(v.s("input"))
        var i = 0
        val res = Rotate.rotateVaultKey(
            input, Session(oldKey.copyOf()),
            RotatePlan(
                password = plan.s("password"), kdf = Kdf.from(plan["kdf"]), recoveryCodes = plan.strList("recoveryCodes"), recoveryKey = plan.s("recoveryKey"),
                prf = mapOf(plan.s("prfCredId") to Bytes.unhex(plan.s("prfOutputHex"))), usbKeyFiles = listOf(plan.s("usbKeyFile")), dropUnknown = true,
            ),
            RotateOptions(iv = ivFor(newKey), rng = { n -> ByteArray(n) { 0x33 } }, newId = { "n${i++}" }, newKey = newKey, now = v.l("now")),
        )
        val out = res.file
        assertEquals("rotated file must be byte-identical to the TypeScript client", v.s("output"), out.toText())
        assertEquals(v.strList("dropped"), res.dropped.map { "${it.type}:${it.id}" }.sorted())
        assertEquals(2L, out.json.l("v"))
        assertEquals(1L, out.keyEpoch)
        VaultFile.validate(out)
        // Every unlock path of the new file gives the new key, and the old secrets give nothing.
        assertArrayEquals(newKey, VaultEngine.unlockWithPassword(out, plan.s("password")).raw)
        assertArrayEquals(newKey, VaultEngine.unlockWithPrf(out, plan.s("prfCredId"), Bytes.unhex(plan.s("prfOutputHex"))).raw)
        assertArrayEquals(newKey, VaultEngine.unlockWithUsbKey(out, plan.s("usbKeyFile")).raw)
        assertArrayEquals(newKey, VaultEngine.unlockWithRecoveryCode(out, plan.strList("recoveryCodes")[1]).first.raw)
        assertArrayEquals(newKey, VaultEngine.unlockWithRecoveryKey(out, plan.s("recoveryKey")).raw)
        for (bad in listOf({ VaultEngine.unlockWithPassword(out, v.o("secrets").s("oldPassword")) }, { VaultEngine.unlockWithRecoveryCode(out, v.o("secrets").s("oldCode")) })) {
            try { bad(); fail("an old secret still unlocks the rotated vault") } catch (_: DecryptError) { }
        }
        for (r in out.entries) {
            try { Crypto.openJson(oldKey, r.sealed, Crypto.Aad.entry(out.id, r.id, r.ver)); fail("old key still opens an item") } catch (_: DecryptError) { }
            Crypto.openJson(newKey, r.sealed, Crypto.Aad.entry(out.id, r.id, r.ver))
        }
        // A client that only knows v1 would refuse this file: v is 2.
        assertFalse(out.json.long("v") == 1L)
        // A v2 file without its epoch is not valid.
        try { VaultFile.validate(VaultFile(out.json.with("keyEpoch" to null))); fail("v2 without keyEpoch must be refused") } catch (_: IllegalArgumentException) { }
        // Refuses to silently drop slot kinds it does not know.
        try {
            Rotate.rotateVaultKey(input, Session(oldKey.copyOf()), RotatePlan("x", Kdf.from(plan["kdf"])))
            fail("unknown slot kinds must stop the rotation")
        } catch (e: IllegalStateException) { assertEquals("unknown-slot", e.message) }
    }
}
