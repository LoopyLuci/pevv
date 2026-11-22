package dev.pevv.app.core

import dev.pevv.app.core.Bytes.b64url
import dev.pevv.app.core.Bytes.concat
import dev.pevv.app.core.Bytes.unb64url
import dev.pevv.app.core.Bytes.utf8
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

/**
 * PEVV as a passkey provider: the same item kind and the same authenticator data as the desktop provider
 * (src/pevv/passkeyProvider.ts). A passkey is a vault item `type: "passkey"` with a P-256 PKCS#8 key inside.
 */
object PasskeyCore {
    /** The authenticator AAGUID. Fixed: it names PEVV to relying parties and matches the desktop shell. */
    const val AAGUID = "661cf2bd-74e1-42fd-93d3-7e2ed09cf977"
    const val COSE_ES256 = -7
    const val FLAG_UP = 0x01
    const val FLAG_UV = 0x04
    const val FLAG_BE = 0x08
    const val FLAG_BS = 0x10
    const val FLAG_AT = 0x40

    fun uuidBytes(uuid: String): ByteArray {
        val hex = uuid.replace("-", "")
        require(Regex("^[0-9a-fA-F]{32}$").matches(hex)) { "not a UUID" }
        return Bytes.unhex(hex.lowercase())
    }

    /** The COSE_Key of an ES256 public key in canonical CBOR: `{1: 2, 3: -7, -1: 1, -2: x, -3: y}`. */
    fun coseKeyEs256(x: ByteArray, y: ByteArray): ByteArray {
        require(x.size == 32 && y.size == 32) { "P-256 coordinates must be 32 bytes" }
        return concat(
            byteArrayOf(0xa5.toByte(), 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20), x,
            byteArrayOf(0x22, 0x58, 0x20), y,
        )
    }

    private fun u32be(n: Long) = byteArrayOf((n ushr 24).toByte(), (n ushr 16).toByte(), (n ushr 8).toByte(), n.toByte())

    /** rpIdHash(32) | flags(1) | signCount(4) | [aaguid(16) | idLen(2) | id | coseKey]. */
    fun buildAuthData(rpIdHash: ByteArray, flags: Int, signCount: Long, credentialId: ByteArray? = null, cosePublicKey: ByteArray? = null): ByteArray {
        require(rpIdHash.size == 32) { "rpIdHash must be 32 bytes" }
        val head = concat(rpIdHash, byteArrayOf(flags.toByte()), u32be(signCount))
        if (credentialId == null || cosePublicKey == null) return head
        require(credentialId.size in 1..1023) { "bad credential id length" }
        val len = byteArrayOf((credentialId.size shr 8).toByte(), (credentialId.size and 0xff).toByte())
        return concat(head, uuidBytes(AAGUID), len, credentialId, cosePublicKey)
    }

    /** CBOR attestation object with the `none` format, for a registration response. */
    fun attestationObjectNone(authData: ByteArray): ByteArray {
        val head = concat(
            byteArrayOf(0xa3.toByte()),
            byteArrayOf(0x63) + utf8("fmt"), byteArrayOf(0x64) + utf8("none"),
            byteArrayOf(0x67) + utf8("attStmt"), byteArrayOf(0xa0.toByte()),
            byteArrayOf(0x68) + utf8("authData"),
        )
        val n = authData.size
        val lenBytes = if (n < 24) byteArrayOf((0x40 + n).toByte()) else if (n < 256) byteArrayOf(0x58, n.toByte()) else byteArrayOf(0x59, (n shr 8).toByte(), (n and 0xff).toByte())
        return concat(head, lenBytes, authData)
    }

    fun validRpId(rpId: String): Boolean =
        rpId.isNotEmpty() && rpId.length <= 253 && Regex("^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$").matches(rpId)

    class Made(val data: JsonObject, val authData: ByteArray, val credentialId: String)

    fun createPasskey(rpId: String, rpName: String?, userHandle: String, userName: String, userDisplayName: String?, userVerified: Boolean, now: Long = System.currentTimeMillis()): Made {
        if (!validRpId(rpId)) throw IllegalArgumentException("bad-rp")
        val uh = unb64url(userHandle)
        if (uh.size < 1 || uh.size > 64) throw IllegalArgumentException("bad-user")
        val g = KeyPairGenerator.getInstance("EC")
        g.initialize(ECGenParameterSpec("secp256r1"))
        val pair = g.generateKeyPair()
        val pub = rawPublic(pair.public as ECPublicKey)
        val pkcs8 = pair.private.encoded
        val credId = Bytes.random(32)
        val fields = LinkedHashMap<String, JsonElement?>()
        fields["title"] = jstr("$rpId (passkey)")
        fields["rpId"] = jstr(rpId)
        if (!rpName.isNullOrEmpty()) fields["rpName"] = jstr(rpName)
        fields["credentialId"] = jstr(b64url(credId))
        fields["userHandle"] = jstr(userHandle)
        fields["userName"] = jstr(userName)
        if (!userDisplayName.isNullOrEmpty()) fields["userDisplayName"] = jstr(userDisplayName)
        fields["passkeyPrivateKey"] = jstr(b64url(pkcs8))
        fields["passkeyPublicKey"] = jstr(b64url(pub))
        fields["signCount"] = jnum(0)
        val data = EntryKinds.newData("passkey", now).with(fields)
        val authData = buildAuthData(
            Crypto.sha256(utf8(rpId)),
            FLAG_UP or FLAG_BE or FLAG_BS or FLAG_AT or (if (userVerified) FLAG_UV else 0), 0,
            credId, coseKeyEs256(pub.copyOfRange(1, 33), pub.copyOfRange(33, 65)),
        )
        return Made(data, authData, b64url(credId))
    }

    /** Uncompressed point: 0x04 | x(32) | y(32). */
    fun rawPublic(k: ECPublicKey): ByteArray {
        fun fit(v: BigInteger): ByteArray {
            val b = v.toByteArray()
            return if (b.size > 32) b.copyOfRange(b.size - 32, b.size) else ByteArray(32 - b.size) + b
        }
        return concat(byteArrayOf(4), fit(k.w.affineX), fit(k.w.affineY))
    }

    class Assertion(val credentialId: String, val authData: ByteArray, val signature: ByteArray, val userHandle: String, val userName: String, val signCount: Long)

    /** Sign an assertion with a stored passkey. `clientDataHash` is the 32-byte hash of the client data. The signature is ASN.1 DER. */
    fun signAssertion(item: JsonObject, clientDataHash: ByteArray, userVerified: Boolean): Assertion {
        require(clientDataHash.size == 32) { "bad-hash" }
        val rpId = item.str("rpId") ?: throw IllegalArgumentException("bad passkey")
        val key = KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(unb64url(item.str("passkeyPrivateKey") ?: throw IllegalArgumentException("bad passkey"))))
        val signCount = ((item.long("signCount") ?: 0) and 0xffffffffL) + 1
        val authData = buildAuthData(Crypto.sha256(utf8(rpId)), FLAG_UP or FLAG_BE or FLAG_BS or (if (userVerified) FLAG_UV else 0), signCount)
        val sig = Signature.getInstance("SHA256withECDSA")
        sig.initSign(key)
        sig.update(concat(authData, clientDataHash))
        return Assertion(item.str("credentialId") ?: "", authData, sig.sign(), item.str("userHandle") ?: "", item.str("userName") ?: "", signCount)
    }

    /** Check an assertion the way a relying party would (tests, and a self-check). */
    fun verifyAssertion(publicKeyRaw: ByteArray, authData: ByteArray, clientDataHash: ByteArray, derSignature: ByteArray): Boolean {
        val spki = byteArrayOf(
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86.toByte(), 0x48, 0xce.toByte(), 0x3d, 0x02, 0x01,
            0x06, 0x08, 0x2a, 0x86.toByte(), 0x48, 0xce.toByte(), 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
        ) + publicKeyRaw
        val pub = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(spki))
        val s = Signature.getInstance("SHA256withECDSA")
        s.initVerify(pub)
        s.update(concat(authData, clientDataHash))
        return s.verify(derSignature)
    }

    /** Passkey items for exactly this rpId (never a parent or sibling domain). */
    fun forRp(entries: List<Entry>, rpId: String): List<Entry> = entries.filter { it.isPasskey && it.s("rpId") == rpId }
}
