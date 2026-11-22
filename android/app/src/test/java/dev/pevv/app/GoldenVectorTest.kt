package dev.pevv.app

import dev.pevv.app.core.Bytes
import dev.pevv.app.core.Crypto
import dev.pevv.app.core.DecryptError
import dev.pevv.app.core.Devices
import dev.pevv.app.core.Import
import dev.pevv.app.core.Json
import dev.pevv.app.core.Kdf
import dev.pevv.app.core.PasskeyCore
import dev.pevv.app.core.Reconcile
import dev.pevv.app.core.ReconcileAction
import dev.pevv.app.core.Recovery
import dev.pevv.app.core.RemoteSource
import dev.pevv.app.core.RosterSlice
import dev.pevv.app.core.Sealed
import dev.pevv.app.core.Session
import dev.pevv.app.core.Totp
import dev.pevv.app.core.TotpConfig
import dev.pevv.app.core.Transfer
import dev.pevv.app.core.TransferError
import dev.pevv.app.core.UsbKeyFile
import dev.pevv.app.core.VaultDevice
import dev.pevv.app.core.VaultEngine
import dev.pevv.app.core.VaultFile
import dev.pevv.app.core.arr
import dev.pevv.app.core.long
import dev.pevv.app.core.obj
import dev.pevv.app.core.str
import dev.pevv.app.core.with
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/** Everything here decrypts or checks data that the TypeScript code made. A mismatch is a bug in the port, never in the vector. */
class GoldenVectorTest {
    private fun kdfOf(o: JsonObject) = Kdf.from(o["kdf"])

    @Test fun argon2idAndPbkdf2MatchTypeScript() {
        for (c in Vectors.arr("kdf")) {
            val o = c.o()
            val raw = Crypto.stretch(o["password"]!!.s(), kdfOf(o))
            assertEquals(o["name"]!!.s(), o["stretchHex"]!!.s(), Bytes.hex(raw))
            val kek = Crypto.passwordKek(o["password"]!!.s(), kdfOf(o))
            assertEquals(o["name"]!!.s(), o["passwordKekHex"]!!.s(), Bytes.hex(kek))
        }
    }

    @Test fun nfcNormalisationGivesTheSameKey() {
        val cases = Vectors.arr("kdf").map { it.o() }.associateBy { it["name"]!!.s() }
        assertEquals(cases["argon2id-nfc-composed"]!!["stretchHex"]!!.s(), cases["argon2id-nfc-decomposed"]!!["stretchHex"]!!.s())
    }

    @Test fun kdfFloorsAreEnforced() {
        val salt = Bytes.b64(ByteArray(16))
        for (bad in listOf(Kdf.Pbkdf2(100_000, salt), Kdf.Argon2id(1024, 1, 1, salt), Kdf.Argon2id(19_456, 2, 1, Bytes.b64(ByteArray(8))), Kdf.Argon2id(19_456, 2, 9, salt))) {
            try {
                Crypto.validateKdf(bad)
                fail("accepted $bad")
            } catch (_: IllegalArgumentException) {
            }
        }
        Crypto.validateKdf(Kdf.Argon2id(19_456, 2, 1, salt))
    }

    @Test fun hkdfMatchesWebCrypto() {
        for (c in Vectors.arr("hkdf")) {
            val o = c.o()
            val okm = Crypto.hkdf(Bytes.unhex(o["ikmHex"]!!.s()), Bytes.unb64(o["salt"]!!.s()), o["info"]!!.s())
            assertEquals(o["okmHex"]!!.s(), Bytes.hex(okm))
        }
    }

    @Test fun aesGcmOpensWebCryptoOutputAndRejectsWrongAad() {
        val o = Vectors.obj("aes")
        val key = Bytes.unhex(o["keyHex"]!!.s())
        val sealed = Sealed.from(o["sealed"])
        assertEquals(o["plainUtf8"]!!.s(), Bytes.fromUtf8(Crypto.open(key, sealed, o["aad"]!!.s())))
        try {
            Crypto.open(key, sealed, o["aad"]!!.s() + "x")
            fail("wrong AAD accepted")
        } catch (_: DecryptError) {
        }
        // Seal here, open with the same call; the reverse (TypeScript opening this) is the kotlin-made fixture.
        val again = Crypto.seal(key, Bytes.utf8("x"), "a")
        assertEquals("x", Bytes.fromUtf8(Crypto.open(key, again, "a")))
    }

    @Test fun base32MatchesTypeScript() {
        for (c in Vectors.arr("base32")) {
            val o = c.o()
            val bytes = Bytes.unhex(o["hex"]!!.s())
            assertEquals(o["base32"]!!.s(), Bytes.base32Encode(bytes))
            assertArrayEquals(bytes, Bytes.base32Decode(o["base32"]!!.s()))
        }
    }

    @Test fun recoveryMaterialMatchesTypeScript() {
        val o = Vectors.obj("recovery")
        assertEquals(o["normalized"]!!.s(), Recovery.normalizeCode("abcde fgh23-4567 2abcde"))
        assertEquals(o["hash"]!!.s(), Recovery.codeHash(o["code"]!!.s(), o["salt"]!!.s()))
        assertEquals(o["codeKekHex"]!!.s(), Bytes.hex(Recovery.codeKek(o["code"]!!.s(), o["salt"]!!.s())))
        assertEquals(o["keyBytesHex"]!!.s(), Bytes.hex(Recovery.recoveryKeyBytes(o["key"]!!.s())))
        assertEquals(o["keyKekHex"]!!.s(), Bytes.hex(Recovery.recoveryKeyKek(o["key"]!!.s(), o["salt"]!!.s())))
    }

    @Test fun totpMatchesRfc6238AndTypeScript() {
        val t = Vectors.obj("totp")
        for (c in t["cases"]!!.a()) {
            val o = c.o()
            val cfg = TotpConfig.from(o["cfg"]!!)
            assertEquals(o["code"]!!.s(), Totp.totpAt(cfg, o["unixMs"]!!.l()))
        }
        for (c in t["uris"]!!.a()) {
            val o = c.o()
            assertEquals(TotpConfig.from(o["cfg"]!!), Totp.parse(o["uri"]!!.s()))
        }
        for (c in t["limiter"]!!.a()) assertEquals(c.o()["delay"]!!.l(), Totp.limiterDelay(c.o()["fails"]!!.l().toInt()))
        val cfg = TotpConfig("JBSWY3DPEHPK3PXP")
        val code = Totp.totpAt(cfg, 1_700_000_000_000)
        assertEquals(1_700_000_000L / 30, Totp.verify(cfg, code, 1_700_000_000_000))
        assertNull("replay", Totp.verify(cfg, code, 1_700_000_000_000, lastStep = 1_700_000_000L / 30))
        assertNull(Totp.verify(cfg, "000000", 1_700_000_000_000))
    }

    private fun unlockedVault(name: String): Triple<JsonObject, VaultFile, Session> {
        val v = Vectors.obj(name)
        val file = VaultFile.parse(Json.encode(v["file"]!!))
        return Triple(v, file, VaultEngine.unlockWithPassword(file, v["password"]!!.s()))
    }

    private fun checkVault(name: String) {
        val (v, file, session) = unlockedVault(name)
        assertEquals(v["vaultKeyHex"]!!.s(), Bytes.hex(session.raw))
        val d = VaultEngine.decryptAll(file, session)
        val exp = v["expected"]!!.o()
        val want = exp["entries"]!!.a().map { it.o() }
        assertEquals(want.size, d.entries.size)
        for (w in want) {
            val got = d.entries.first { it.id == w["id"]!!.s() }
            assertEquals(w["ver"]!!.l(), got.ver)
            assertEquals("entry ${w["id"]!!.s()}", w["data"]!!.o(), got.data)
        }
        assertEquals(exp["meta"]!!.o(), d.meta.json)
        assertEquals(exp["warnings"]!!.a().map { it.s() }, d.warnings)
        val t = exp["totp"]
        if (t == null || t is JsonNull) assertNull(d.totp) else assertEquals(TotpConfig.from(t), d.totp)
    }

    @Test fun argon2idVaultDecryptsWithEverySlotType() {
        checkVault("vault-argon2id")
        val (v, file, session) = unlockedVault("vault-argon2id")
        val ex = v["extras"]!!.o()
        for (code in ex["recoveryCodes"]!!.a()) {
            val (s, slot) = VaultEngine.unlockWithRecoveryCode(file, code.s().lowercase())
            assertArrayEquals(session.raw, s.raw)
            assertTrue(file.slots.any { it.id == slot && it.type == "recovery-code" })
        }
        assertArrayEquals(session.raw, VaultEngine.unlockWithRecoveryKey(file, ex["recoveryKey"]!!.s()).raw)
        assertArrayEquals(session.raw, VaultEngine.unlockWithUsbKey(file, ex["usbKeyFile"]!!.s()).raw)
        val prf = ex["prf"]!!.o()
        assertArrayEquals(session.raw, VaultEngine.unlockWithPrf(file, prf["credId"]!!.s(), Bytes.unhex(prf["outputHex"]!!.s())).raw)
        // The second-factor key file is not an unlock key, but it satisfies the gate.
        val meta = VaultEngine.readMeta(file, session)
        assertTrue(VaultEngine.checkUsbKeyFactor(file, session, meta, ex["usbGateFile"]!!.s()))
        assertTrue(VaultEngine.checkUsbKeyFactor(file, session, meta, ex["usbKeyFile"]!!.s()))
        assertFalse(VaultEngine.checkUsbKeyFactor(file, session, meta, UsbKeyFile.create(file.id).text))
        try {
            VaultEngine.unlockWithUsbKey(file, ex["usbGateFile"]!!.s())
            fail("a gate-only key file must not unlock")
        } catch (_: DecryptError) {
        }
        val status = VaultEngine.recoveryStatus(file)
        assertEquals(3, status.codes)
        assertTrue(status.key)
        assertEquals(1, status.prf)
        assertEquals(1, status.usb)
    }

    @Test fun pbkdf2VaultDecrypts() = checkVault("vault-pbkdf2")

    @Test fun wrongPasswordFailsClosed() {
        val v = Vectors.obj("vault-argon2id")
        val file = VaultFile.parse(Json.encode(v["file"]!!))
        try {
            VaultEngine.unlockWithPassword(file, "wrong")
            fail("wrong password accepted")
        } catch (_: DecryptError) {
        }
    }

    @Test fun movedOrReplayedRecordsAreRejected() {
        val (_, file, session) = unlockedVault("vault-pbkdf2")
        // An entry sealed for version n must not open as another id or version.
        val rec = file.entries.first()
        for (aad in listOf(Crypto.Aad.entry(file.id, rec.id, rec.ver + 1), Crypto.Aad.entry(file.id, file.entries[1].id, rec.ver), Crypto.Aad.entry("x" + file.id, rec.id, rec.ver))) {
            try {
                Crypto.open(session.raw, rec.sealed, aad)
                fail("accepted wrong AAD $aad")
            } catch (_: DecryptError) {
            }
        }
        // The sealed meta is bound to the revision.
        try {
            VaultEngine.decryptAll(file.with(mapOf("rev" to JsonPrimitive(file.rev + 1))), session)
            fail("meta accepted at the wrong revision")
        } catch (_: DecryptError) {
        }
    }

    @Test fun portableExportsKitAndHandoffOpen() {
        val t = Vectors.obj("transfer")
        val v2 = t["exportV2"]!!.o()
        val opened = VaultEngine.openExport(Json.encode(v2["file"]!!), v2["password"]!!.s()) as VaultEngine.Opened.Vault
        assertEquals(v2["vaultId"]!!.s(), opened.file.id)
        assertEquals(2, VaultEngine.peekExport(Json.encode(v2["file"]!!)))
        val v1 = t["exportV1"]!!.o()
        val items = VaultEngine.openExport(Json.encode(v1["file"]!!), v1["password"]!!.s()) as VaultEngine.Opened.Items
        assertEquals(v1["itemCount"]!!.l().toInt(), items.entries.size)
        assertEquals(1, VaultEngine.peekExport(Json.encode(v1["file"]!!)))
        assertEquals(0, VaultEngine.peekExport("{}"))
        try {
            VaultEngine.openExport(Json.encode(v2["file"]!!), "nope")
            fail()
        } catch (_: DecryptError) {
        }
        val kit = t["kit"]!!.o()
        assertEquals(kit["recoveryKey"]!!.s(), Recovery.openKit(Json.encode(kit["file"]!!), kit["passphrase"]!!.s()))
        val h = t["handoff"]!!.o()
        assertEquals(h["plain"]!!.s(), Transfer.openHandoff(h["envelope"]!!.o(), h["key"]!!.s(), h["now"]!!.l()))
        for ((now, code) in listOf(h["expired"]!!.l() to "qr-expired")) {
            try {
                Transfer.openHandoff(h["envelope"]!!.o(), h["key"]!!.s(), now)
                fail()
            } catch (e: TransferError) {
                assertEquals(code, e.code)
            }
        }
        try {
            Transfer.openHandoff(h["envelope"]!!.o(), Bytes.b64url(ByteArray(32)), h["now"]!!.l())
            fail()
        } catch (e: TransferError) {
            assertEquals("qr-damaged", e.code)
        }
    }

    @Test fun offlineFramesRoundTripBothWays() {
        val f = Vectors.obj("transfer")["frames"]!!.o()
        val frames = f["frames"]!!.a().map { it.s() }
        val file = Transfer.unpackFrames(frames.reversed())
        assertEquals(f["vaultText"]!!.s(), file.toText())
        // Frames made here must read back, and carry the same header shape.
        val mine = Transfer.packVault(file)
        assertEquals(frames.size, mine.size)
        assertEquals(f["vaultText"]!!.s(), Transfer.unpackFrames(mine).toText())
        assertTrue(mine.all { Transfer.parseFrame(it) != null })
        try {
            Transfer.unpackFrames(frames.dropLast(1).ifEmpty { listOf("PEVV1|0|2|00000000|") })
            fail()
        } catch (e: TransferError) {
            assertTrue(e.code == "qr-incomplete" || e.code == "qr-damaged")
        }
    }

    @Test fun scansAndShareLinks() {
        val t = Vectors.obj("transfer")
        for (c in t["scans"]!!.a()) {
            val o = c.o()
            val hit = Transfer.parseScan(o["text"]!!.s())
            when (o["kind"]!!.s()) {
                "frame" -> assertEquals(o["value"]!!.s(), (hit as Transfer.ScanHit.FrameHit).frame)
                "handoff" -> {
                    val h = hit as Transfer.ScanHit.HandoffHit
                    assertEquals(o["key"]!!.s(), h.key)
                    assertEquals(o["xfer"]?.takeIf { it !is JsonNull }?.s(), h.xfer)
                }
                else -> assertNull(hit)
            }
        }
        for (c in t["shareUrl"]!!.a()) assertEquals(c.o()["url"]!!.s(), Transfer.shareUrl(c.o()["token"]!!.s(), c.o()["base"]!!.s()))
        assertEquals("H.k", Transfer.shareUrl("H.k", ""))
    }

    private fun slice(o: JsonObject) = RosterSlice(Devices.asDevices(o["devices"]), o.arr("revokedDevices")!!.map { it.s() })

    private fun deviceOf(e: kotlinx.serialization.json.JsonElement): VaultDevice = Devices.asDevices(JsonArray(listOf(e))).first()

    @Test fun rosterMergeMatchesTypeScript() {
        for (c in Vectors.arr("roster")) {
            val o = c.o()
            val a = slice(o["a"]!!.o())
            val b = slice(o["b"]!!.o())
            val merged = Devices.mergeRoster(a, b)
            val want = slice(o["merged"]!!.o())
            assertEquals(want.revokedDevices, merged.revokedDevices)
            assertEquals(want.devices, merged.devices)
            assertEquals(o["same"]!!.b(), Devices.sameRoster(a, b))
            assertEquals(o["sameMerged"]!!.b(), Devices.sameRoster(a, merged))
        }
        val ad = Vectors.obj("asDevices")
        assertEquals(Devices.asDevices(ad["expected"]), Devices.asDevices(JsonArray(ad["input"]!!.a())))
        for (c in Vectors.arr("needsWrite")) {
            val o = c.o()
            val prev = o["prev"]?.takeIf { it !is JsonNull }?.let(::deviceOf)
            assertEquals(o["needs"]!!.b(), Devices.deviceNeedsWrite(prev, deviceOf(o["next"]!!)))
        }
    }

    @Test fun reconcileRulesMatchTypeScript() {
        for (c in Vectors.arr("reconcile")) {
            val o = c.o()
            val local = o["local"]?.takeIf { it !is JsonNull }?.o()
            val remote = o["remote"]!!.o()
            val got = Reconcile.decide(
                hasLocal = local != null, localId = local?.str("id") ?: "", localRev = local?.long("rev") ?: 0,
                remoteId = remote.str("id")!!, remoteRev = remote.long("rev")!!, unlocked = o["unlocked"]!!.b(),
                source = if (o["source"]!!.s() == "cloud") RemoteSource.CLOUD else RemoteSource.PEER,
                prefSync = o["prefSync"]!!.b(), revokedLocally = o["revokedLocally"]!!.b(),
            )
            val want = when (o["expect"]!!.s()) { "adopt" -> ReconcileAction.ADOPT; "merge-roster" -> ReconcileAction.MERGE_ROSTER; else -> ReconcileAction.IGNORE }
            assertEquals(o["name"]!!.s(), want, got)
        }
    }

    @Test fun passkeysInteroperateWithTheDesktopProvider() {
        val p = Vectors.obj("passkey")
        val item = p["item"]!!.o()
        val pub = Bytes.unhex(p["publicKeyHex"]!!.s())
        val hash = Bytes.unhex(p["clientDataHashHex"]!!.s())
        // The assertion TypeScript signed verifies here...
        val a = p["assertion"]!!.o()
        assertTrue(PasskeyCore.verifyAssertion(pub, Bytes.unhex(a["authDataHex"]!!.s()), hash, Bytes.unhex(a["signatureHex"]!!.s())))
        // ...and one Kotlin signs with the TypeScript key verifies, with the same authData shape.
        val mine = PasskeyCore.signAssertion(item, hash, true)
        assertEquals(a["signCount"]!!.l(), mine.signCount)
        assertEquals(a["authDataHex"]!!.s(), Bytes.hex(mine.authData))
        assertTrue(PasskeyCore.verifyAssertion(pub, mine.authData, hash, mine.signature))
        assertEquals(p["rpIdHashHex"]!!.s(), Bytes.hex(mine.authData.copyOfRange(0, 32)))
        val flip = hash.clone().also { it[0] = (it[0].toInt() xor 1).toByte() }
        assertFalse(PasskeyCore.verifyAssertion(pub, mine.authData, flip, mine.signature))
        // COSE key and AAGUID.
        assertEquals(p["cosePublicKeyHex"]!!.s(), Bytes.hex(PasskeyCore.coseKeyEs256(pub.copyOfRange(1, 33), pub.copyOfRange(33, 65))))
        assertEquals(p["aaguid"]!!.s(), PasskeyCore.AAGUID)
        val creation = Bytes.unhex(p["creationAuthDataHex"]!!.s())
        assertEquals(p["aaguid"]!!.s().replace("-", ""), Bytes.hex(creation.copyOfRange(37, 53)))
    }

    @Test fun kotlinPasskeyHasTheSameStructureAsTypeScript() {
        val made = PasskeyCore.createPasskey("example.org", "Example", Bytes.b64url(byteArrayOf(1, 2, 3, 4)), "alice", "Alice", true, 1L)
        val ts = Vectors.obj("passkey")["item"]!!.o()
        assertEquals(ts.keys, made.data.keys)
        assertEquals("passkey", made.data.str("type"))
        val pub = Bytes.unb64url(made.data.str("passkeyPublicKey")!!)
        assertEquals(65, pub.size)
        val ad = made.authData
        // rpIdHash | flags | count | aaguid | len | credId | cose
        assertEquals(0x01 or 0x04 or 0x08 or 0x10 or 0x40, ad[32].toInt() and 0xff)
        assertEquals(0, ad.copyOfRange(33, 37).sumOf { it.toInt() })
        assertEquals(Vectors.obj("passkey")["aaguid"]!!.s().replace("-", ""), Bytes.hex(ad.copyOfRange(37, 53)))
        assertEquals(32, ((ad[53].toInt() and 0xff) shl 8) or (ad[54].toInt() and 0xff))
        val hash = Bytes.random(32)
        val a = PasskeyCore.signAssertion(made.data, hash, true)
        assertTrue(PasskeyCore.verifyAssertion(pub, a.authData, hash, a.signature))
        assertEquals(1L, a.signCount)
        // CBOR attestation object: a3 63 'fmt' 64 'none' ...
        val att = PasskeyCore.attestationObjectNone(ad)
        assertEquals(0xa3, att[0].toInt() and 0xff)
        assertEquals("fmt", String(att, 2, 3))
        assertTrue(att.size > ad.size)
    }

    @Test fun importsMatchTypeScript() {
        for (c in Vectors.arr("imports")) {
            val o = c.o()
            val r = Import.importManagerExport(o["text"]!!.s(), 1_700_000_000_000)
            val want = o["result"]!!.o()
            assertEquals(o["name"]!!.s(), want["source"]!!.s(), r.source)
            assertEquals(o["name"]!!.s(), want["skipped"]!!.l().toInt(), r.skipped)
            assertEquals(o["name"]!!.s(), want["entries"]!!.a().map { it.o() }, r.entries)
        }
        try {
            Import.importManagerExport("-----BEGIN PGP MESSAGE-----\nx")
            fail()
        } catch (_: IllegalArgumentException) {
        }
    }

    @Test fun dotenvMatchesTypeScript() {
        val d = Vectors.obj("dotenv")
        val parsed = Import.parseDotenv(d["text"]!!.s())
        assertEquals(d["parsed"]!!.a().map { it.o()["name"]!!.s() to it.o()["value"]!!.s() }, parsed)
        val ser = Import.serializeDotenv(listOf("A" to "plain/ok", "B" to "with space", "C" to "q\"uote\nnl\\bs", "1bad" to "x"))
        assertEquals(d["serialized"]!!.s(), ser)
    }

    @Test fun entryDataKeepsUnknownFieldsThroughAnEdit() {
        val (_, file, session) = unlockedVault("vault-argon2id")
        val d = VaultEngine.decryptAll(file, session)
        val login = d.entries.first { it.type == "login" }
        assertNotNull(login.data["futureField"])
        val edited = dev.pevv.app.core.EntryKinds.applyEdit(login.data, mapOf("password" to JsonPrimitive("new-pass")), 5)
        val (f2, m2, e2) = VaultEngine.putEntry(file, session, d.meta, login.id, edited)
        assertEquals(login.ver + 1, e2.ver)
        assertEquals(file.rev + 1, f2.rev)
        val back = VaultEngine.decryptAll(f2, session)
        val again = back.entries.first { it.id == login.id }
        assertEquals(login.data["futureField"], again.data["futureField"])
        assertEquals("new-pass", again.password)
        assertEquals(login.password, again.history.first().str("value"))
        assertEquals(emptyList<String>(), back.warnings)
        assertEquals(m2.json, back.meta.json)
        // unknown meta fields survive too
        assertNotNull(back.meta.json["futureMetaField"])
    }

    @Test fun unknownSlotTypesAreSkippedNotRejected() {
        val (_, file, session) = unlockedVault("vault-pbkdf2")
        val slots = JsonArray(file.json.arr("slots")!! + Json.parseObject("""{"id":"zz","type":"from-the-future","wrapped":{"iv":"AA","ct":"AA"}}"""))
        val f2 = VaultFile.parse(Json.encode(file.json.with("slots" to slots)))
        assertArrayEquals(session.raw, VaultEngine.unlockWithPassword(f2, "pb kdf ünicode").raw)
    }

}
