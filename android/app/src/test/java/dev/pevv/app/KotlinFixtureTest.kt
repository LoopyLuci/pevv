package dev.pevv.app

import dev.pevv.app.core.Bytes
import dev.pevv.app.core.Crypto
import dev.pevv.app.core.EntryKinds
import dev.pevv.app.core.Json
import dev.pevv.app.core.Kdf
import dev.pevv.app.core.PasskeyCore
import dev.pevv.app.core.Recovery
import dev.pevv.app.core.Totp
import dev.pevv.app.core.TotpConfig
import dev.pevv.app.core.Transfer
import dev.pevv.app.core.VaultEngine
import dev.pevv.app.core.VaultFile
import dev.pevv.app.core.jnum
import dev.pevv.app.core.jstr
import dev.pevv.app.core.jstrs
import dev.pevv.app.core.with
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Builds a vault with the Kotlin engine (every slot type, every item kind, exports, a kit, QR frames, a handoff and a passkey) and,
 * when PEVV_WRITE_FIXTURES=1, writes it to vectors/kotlin-made.json. The TypeScript test tests/unit/pevv.android.test.ts opens that
 * file with the web app's own code. Run `PEVV_WRITE_FIXTURES=1 ./gradlew :app:testDebugUnitTest` to refresh the committed fixture.
 */
class KotlinFixtureTest {
    private val T = 1_700_000_000_000L
    private val password = "kotlin made é✓ password"

    private fun item(type: String, vararg kv: Pair<String, JsonElement?>): JsonObject = EntryKinds.newData(type, T).with(*kv)

    @Test fun buildAndSelfCheckTheKotlinFixture() {
        val kdf = Kdf.Argon2id(19_456, 2, 1, Bytes.b64(ByteArray(16) { (it * 3 + 1).toByte() }))
        var (file, session) = VaultEngine.createVault(password, kdf, T)
        var meta = VaultEngine.readMeta(file, session)
        val items = listOf(
            item("login", "title" to jstr("Kotlin login"), "site" to jstr("https://kotlin.example"), "username" to jstr("k@example.com"), "password" to jstr("päss😀"), "totp" to jstr("JBSWY3DPEHPK3PXP"), "notes" to jstr("a\nb"), "tags" to jstrs(listOf("t1")), "futureField" to buildJsonObject { put("x", 1) }),
            item("env", "title" to jstr("API_URL"), "name" to jstr("API_URL"), "value" to jstr("https://api.example?a=\"b\""), "env" to jstr("prod")),
            item("note", "title" to jstr("Note"), "notes" to jstr("secret note")),
            item("apikey", "title" to jstr("Key"), "service" to jstr("svc"), "key" to jstr("sk_live_1")),
            item("card", "title" to jstr("Card"), "cardholder" to jstr("K"), "number" to jstr("4111111111111111"), "expiry" to jstr("01/32"), "cvv" to jstr("999")),
            item("ssh", "title" to jstr("SSH"), "privateKey" to jstr("-----BEGIN OPENSSH PRIVATE KEY-----\nx\n-----END OPENSSH PRIVATE KEY-----"), "publicKey" to jstr("ssh-ed25519 AAAA k@h")),
            item("identity", "title" to jstr("Me"), "fullName" to jstr("K Person"), "email" to jstr("me@example.com")),
        )
        val ids = ArrayList<String>()
        for (d in items) {
            val r = VaultEngine.putEntry(file, session, meta, null, d)
            file = r.first; meta = r.second; ids.add(r.third.id)
        }
        val made = PasskeyCore.createPasskey("example.net", "Example", Bytes.b64url(byteArrayOf(9, 8, 7)), "kim", "Kim", true, T)
        val pk = VaultEngine.putEntry(file, session, meta, null, made.data)
        file = pk.first; meta = pk.second
        // an edit, so the history and ver 2 are in the fixture
        val edited = EntryKinds.applyEdit(items[0], mapOf("password" to jstr("changed-password")), T + 1)
        val ed = VaultEngine.putEntry(file, session, meta, ids[0], edited)
        file = ed.first; meta = ed.second
        val rc = VaultEngine.replaceRecoveryCodes(file, session, meta, 2)
        file = rc.first
        val rk = VaultEngine.replaceRecoveryKey(file, session, meta)
        file = rk.first
        val usb = VaultEngine.addUsbKey(file, session, meta, "Kotlin stick", true)
        file = usb.first
        val prfOut = ByteArray(32) { (it * 9 + 5).toByte() }
        file = VaultEngine.addPrfSlot(file, session, meta, "kotlin-cred", prfOut)
        val tt = VaultEngine.setTotp(file, session, meta, TotpConfig("JBSWY3DPEHPK3PXP", 6, 30))
        file = tt.first; meta = tt.second
        val dev = buildJsonObject {
            put("id", "cccccccc-1111-2222-3333-dddddddddddd"); put("name", "Pixel"); put("kind", "phone"); put("added", T); put("seen", T + 9); put("agent", "PEVV app · Android")
        }
        meta = meta.with(mapOf("devices" to JsonArray(listOf(dev))))
        file = VaultEngine.saveMeta(file, session, meta)

        // self check: everything opens again with the same engine
        val d = VaultEngine.decryptAll(file, session)
        assertEquals(emptyList<String>(), d.warnings)
        assertEquals(8, d.entries.size)

        val dec = VaultEngine.decryptAll(file, session)
        val exportKdf = Kdf.Argon2id(19_456, 2, 1, Bytes.b64(ByteArray(16) { (it + 40).toByte() }))
        val export = VaultEngine.exportPortable(file, "kotlin export pw", exportKdf, "2023-11-14T22:13:20.000Z")
        val kit = Recovery.buildKit(file.id, rk.second, "kotlin kit pw", exportKdf, "2023-11-14T22:13:20.000Z")

        // a small vault for the QR formats (the big one does not fit in 12 frames)
        var (small, sSession) = VaultEngine.createVault("kotlin qr", kdf, T)
        val sMeta = VaultEngine.readMeta(small, sSession)
        small = VaultEngine.putEntry(small, sSession, sMeta, null, items[0]).first
        val frames = Transfer.packVault(small)
        val hand = Transfer.sealHandoff(small.toText(), T, 180_000)

        val hash = ByteArray(32) { (it * 7 + 1).toByte() }
        val assertion = PasskeyCore.signAssertion(made.data, hash, true)

        val out = buildJsonObject {
            put("password", password)
            put("file", file.json)
            put("vaultKeyHex", Bytes.hex(session.raw))
            put("recoveryCodes", jstrs(rc.second))
            put("recoveryKey", rk.second)
            put("usbKeyFile", usb.third)
            put("prf", buildJsonObject { put("credId", "kotlin-cred"); put("outputHex", Bytes.hex(prfOut)) })
            put("expectedEntries", JsonArray(dec.entries.map { e -> buildJsonObject { put("id", e.id); put("ver", e.ver); put("data", e.data) } }))
            put("expectedMeta", dec.meta.json)
            put("expectedTotp", dec.totp!!.toJson())
            put("exportV2", buildJsonObject { put("password", "kotlin export pw"); put("file", export) })
            put("kit", buildJsonObject { put("passphrase", "kotlin kit pw"); put("file", kit); put("recoveryKey", rk.second) })
            put("qr", buildJsonObject { put("frames", jstrs(frames)); put("vaultText", small.toText()); put("password", "kotlin qr") })
            put("handoff", buildJsonObject { put("key", hand.key); put("envelope", hand.envelope); put("plain", small.toText()); put("now", T + 1000) })
            put("passkey", buildJsonObject {
                put("rpId", "example.net")
                put("item", made.data)
                put("clientDataHashHex", Bytes.hex(hash))
                put("authDataHex", Bytes.hex(assertion.authData))
                put("signatureHex", Bytes.hex(assertion.signature))
                put("creationAuthDataHex", Bytes.hex(made.authData))
            })
            put("totpCode", buildJsonObject { put("unixMs", T); put("code", Totp.totpAt(TotpConfig("JBSWY3DPEHPK3PXP", 6, 30), T)) })
        }
        // The fixture also has to parse as a vault with the file-level checks.
        VaultFile.parse(Json.encode(file.json))
        assertTrue(Json.encode(out).length > 1000)
        assertEquals(Crypto.Aad.meta(file.id, file.rev), "luciverse/pevv/v1/meta/${file.id}/${file.rev}")
        assertEquals(JsonPrimitive(file.rev), file.json["rev"])
        assertEquals(jnum(file.rev), file.json["rev"])

        if (System.getenv("PEVV_WRITE_FIXTURES") == "1") {
            File(Vectors.dir, "kotlin-made.json").writeText(Json.encodePretty(out) + "\n", Charsets.UTF_8)
        }
    }
}
