package dev.pevv.app.passkey

import android.app.Activity
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.CredentialManager
import androidx.credentials.GetCredentialRequest
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PublicKeyCredential
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.exceptions.CreateCredentialException
import dev.pevv.app.core.Bytes
import dev.pevv.app.core.Crypto
import dev.pevv.app.core.Json
import dev.pevv.app.core.VaultFile
import dev.pevv.app.core.bool
import dev.pevv.app.core.jstr
import dev.pevv.app.core.long
import dev.pevv.app.core.obj
import dev.pevv.app.core.str
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec

/**
 * Unlocking with, and using as a second factor, a passkey the web app enrolled (a `prf` slot or a `2fa` record), through the
 * platform Credential Manager. The relying party id is the one the web app uses (`PEVV_RP_ID`, a build setting); the passkey must be
 * available on this phone (a synced passkey, or a security key over NFC/USB). PRF needs a credential provider that implements it:
 * where the phone's provider does not, the call fails with a clear message and the password still works.
 */
object PasskeyAuth {
    class Result(val credId: String, val prfOutput: ByteArray?, val signCount: Long)

    class Unsupported(msg: String) : Exception(msg)

    private fun requestJson(rpId: String, challenge: ByteArray, creds: List<Pair<String, String?>>): String = Json.encode(buildJsonObject {
        put("challenge", Bytes.b64url(challenge))
        put("rpId", rpId)
        put("timeout", 60000)
        put("userVerification", "required")
        put("allowCredentials", buildJsonArray { for ((id, _) in creds) add(buildJsonObject { put("type", "public-key"); put("id", id) }) })
        val withPrf = creds.filter { it.second != null }
        if (withPrf.isNotEmpty()) put("extensions", buildJsonObject {
            put("prf", buildJsonObject {
                put("evalByCredential", buildJsonObject { for ((id, salt) in withPrf) put(id, buildJsonObject { put("first", Bytes.b64url(Bytes.unb64(salt!!))) }) })
            })
        })
    })

    private suspend fun get(activity: Activity, json: String): JsonObject {
        val cm = CredentialManager.create(activity)
        val res = try {
            cm.getCredential(activity, GetCredentialRequest(listOf(GetPublicKeyCredentialOption(json))))
        } catch (e: GetCredentialException) {
            throw Unsupported(e.message ?: "passkey failed")
        }
        val cred = res.credential as? PublicKeyCredential ?: throw Unsupported("no passkey returned")
        return Json.parseObject(cred.authenticationResponseJson)
    }

    fun prfCreds(file: VaultFile, credIds: List<String>): List<Pair<String, String?>> {
        val recs = file.passkeys.mapNotNull { it as? JsonObject }
        return credIds.map { id -> id to recs.firstOrNull { it.str("id") == id }?.str("prfSalt") }
    }

    /** One get() that evaluates PRF for every prf-mode credential offered. */
    suspend fun assertPrf(activity: Activity, rpId: String, creds: List<Pair<String, String?>>): Result {
        val challenge = Bytes.random(32)
        val resp = get(activity, requestJson(rpId, challenge, creds))
        val id = resp.str("id") ?: throw Unsupported("no id")
        val prf = resp.obj("clientExtensionResults")?.obj("prf")?.obj("results")?.str("first")
        val auth = Bytes.unb64url(resp.obj("response")?.str("authenticatorData") ?: "")
        return Result(id, prf?.let { Bytes.unb64url(it) }, signCount(auth))
    }

    /** Second-factor gate: the signature must verify against the public key stored in the vault. */
    suspend fun assertGate(activity: Activity, rpId: String, file: VaultFile): Result {
        val recs = file.passkeys.mapNotNull { it as? JsonObject }.filter { it.str("rpId").let { r -> r == null || r.isEmpty() || r == rpId } }
        if (recs.isEmpty()) throw Unsupported("no passkey for this site")
        val challenge = Bytes.random(32)
        val resp = get(activity, requestJson(rpId, challenge, recs.map { (it.str("id") ?: "") to null }))
        val id = resp.str("id") ?: throw Unsupported("no id")
        val rec = recs.firstOrNull { it.str("id") == id } ?: throw Unsupported("unknown passkey")
        val r = resp.obj("response") ?: throw Unsupported("damaged response")
        val clientData = Bytes.unb64url(r.str("clientDataJSON") ?: "")
        val authData = Bytes.unb64url(r.str("authenticatorData") ?: "")
        val sig = Bytes.unb64url(r.str("signature") ?: "")
        val cd = Json.parseObject(Bytes.fromUtf8(clientData))
        if (cd.str("type") != "webauthn.get" || cd.str("challenge") != Bytes.b64url(challenge)) throw Unsupported("passkey check failed")
        if (!checkAuthData(authData, rpId)) throw Unsupported("passkey check failed")
        val pub = rec.str("publicKey")
        if (pub != null && !verify(rec.long("alg")?.toInt() ?: -7, Bytes.unb64(pub), Bytes.concat(authData, Crypto.sha256(clientData)), sig)) throw Unsupported("passkey check failed")
        return Result(id, null, signCount(authData))
    }

    fun checkAuthData(authData: ByteArray, rpId: String): Boolean =
        authData.size >= 37 && Bytes.ctEqual(authData.copyOfRange(0, 32), Crypto.sha256(Bytes.utf8(rpId))) && (authData[32].toInt() and 0x01) != 0

    fun signCount(authData: ByteArray): Long =
        if (authData.size >= 37) ((authData[33].toLong() and 0xff) shl 24) or ((authData[34].toLong() and 0xff) shl 16) or ((authData[35].toLong() and 0xff) shl 8) or (authData[36].toLong() and 0xff) else 0

    /** Verifies an ES256 (-7) or RS256 (-257) assertion signature with an SPKI public key. */
    fun verify(alg: Int, spki: ByteArray, signed: ByteArray, sig: ByteArray): Boolean = try {
        when (alg) {
            -7 -> Signature.getInstance("SHA256withECDSA").run { initVerify(KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(spki))); update(signed); verify(sig) }
            -257 -> Signature.getInstance("SHA256withRSA").run { initVerify(KeyFactory.getInstance("RSA").generatePublic(X509EncodedKeySpec(spki))); update(signed); verify(sig) }
            else -> false
        }
    } catch (_: Exception) {
        false
    }

    class Enrolled(val record: JsonObject, val prfOutput: ByteArray?)

    /** Make a new passkey for the web app's relying party and enrol it (PRF when this phone's provider supports it). */
    suspend fun enrol(activity: Activity, rpId: String, vaultId: String, name: String, wantPrf: Boolean): Enrolled {
        val prfSalt = Bytes.random(32)
        val challenge = Bytes.random(32)
        val json = Json.encode(buildJsonObject {
            put("challenge", Bytes.b64url(challenge))
            put("rp", buildJsonObject { put("id", rpId); put("name", "PEVV") })
            put("user", buildJsonObject { put("id", Bytes.b64url(Bytes.utf8(vaultId))); put("name", "PEVV vault"); put("displayName", "PEVV vault") })
            put("pubKeyCredParams", buildJsonArray { add(buildJsonObject { put("type", "public-key"); put("alg", -7) }); add(buildJsonObject { put("type", "public-key"); put("alg", -257) }) })
            put("timeout", 60000)
            put("attestation", "none")
            put("authenticatorSelection", buildJsonObject { put("residentKey", "preferred"); put("userVerification", "required") })
            if (wantPrf) put("extensions", buildJsonObject { put("prf", buildJsonObject { put("eval", buildJsonObject { put("first", Bytes.b64url(prfSalt)) }) }) })
        })
        val cm = CredentialManager.create(activity)
        val res = try {
            cm.createCredential(activity, CreatePublicKeyCredentialRequest(json)) as CreatePublicKeyCredentialResponse
        } catch (e: CreateCredentialException) {
            throw Unsupported(e.message ?: "passkey failed")
        }
        val o = Json.parseObject(res.registrationResponseJson)
        val id = o.str("id") ?: throw Unsupported("no id")
        val r = o.obj("response")
        val prf = o.obj("clientExtensionResults")?.obj("prf")
        val out = prf?.obj("results")?.str("first")?.let { Bytes.unb64url(it) }
        val mode = if (wantPrf && (prf?.bool("enabled") == true || out != null)) "prf" else "2fa"
        val now = System.currentTimeMillis()
        val rec = buildJsonObject {
            put("id", id); put("name", name.trim().take(40).ifEmpty { "Android passkey" }); put("mode", mode)
            put("publicKey", r?.str("publicKey")?.let { Bytes.b64(Bytes.unb64url(it)) }?.let { jstr(it) } ?: kotlinx.serialization.json.JsonNull)
            put("alg", r?.long("publicKeyAlgorithm") ?: -7L)
            put("transports", (r?.get("transports") as? JsonArray) ?: JsonArray(emptyList()))
            put("prfSalt", if (mode == "prf") jstr(Bytes.b64(prfSalt)) else kotlinx.serialization.json.JsonNull)
            put("created", now); put("lastUsed", kotlinx.serialization.json.JsonNull); put("signCount", 0); put("rpId", rpId)
        }
        return Enrolled(rec, if (mode == "prf") out else null)
    }
}
