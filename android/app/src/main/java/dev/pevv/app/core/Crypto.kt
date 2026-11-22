package dev.pevv.app.core

import dev.pevv.app.core.Bytes.b64
import dev.pevv.app.core.Bytes.unb64
import dev.pevv.app.core.Bytes.utf8
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator
import org.bouncycastle.crypto.params.Argon2Parameters
import org.bouncycastle.crypto.params.KeyParameter
import java.security.MessageDigest
import java.text.Normalizer
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** A wrong secret or a damaged record. GCM cannot tell the two apart, and neither can we. */
class DecryptError(msg: String = "wrong secret or damaged data") : Exception(msg)

/** `{ iv, ct }`, both base64: 12-byte IV and ciphertext followed by the 16-byte GCM tag. */
data class Sealed(val iv: String, val ct: String) {
    fun toJson(): JsonObject = buildJsonObject {
        put("iv", iv)
        put("ct", ct)
    }

    companion object {
        fun from(e: JsonElement?): Sealed {
            val o = e as? JsonObject ?: throw DecryptError("damaged record")
            val iv = (o["iv"] as? JsonPrimitive)?.takeIf { it.isString }?.content
            val ct = (o["ct"] as? JsonPrimitive)?.takeIf { it.isString }?.content
            if (iv == null || ct == null) throw DecryptError("damaged record")
            return Sealed(iv, ct)
        }
    }
}

sealed class Kdf {
    abstract val salt: String
    abstract fun toJson(): JsonObject

    data class Argon2id(val m: Int, val t: Int, val p: Int, override val salt: String) : Kdf() {
        override fun toJson() = buildJsonObject {
            put("alg", "argon2id")
            put("m", m)
            put("t", t)
            put("p", p)
            put("salt", salt)
        }
    }

    data class Pbkdf2(val iter: Int, override val salt: String) : Kdf() {
        override fun toJson() = buildJsonObject {
            put("alg", "pbkdf2-sha256")
            put("iter", iter)
            put("salt", salt)
        }
    }

    companion object {
        fun from(e: JsonElement?): Kdf {
            val o = e as? JsonObject ?: throw IllegalArgumentException("unknown KDF")
            val salt = o.str("salt") ?: throw IllegalArgumentException("KDF salt missing")
            return when (o.str("alg")) {
                "argon2id" -> Argon2id(o.int("m") ?: 0, o.int("t") ?: 0, o.int("p") ?: 0, salt)
                "pbkdf2-sha256" -> Pbkdf2(o.int("iter") ?: 0, salt)
                else -> throw IllegalArgumentException("unknown KDF")
            }
        }
    }
}

/** Key derivation, HKDF and AES-256-GCM. A line-by-line port of src/pevv/crypto.ts. */
object Crypto {
    const val PBKDF2_MIN_ITER = 600_000
    const val PBKDF2_MAX_ITER = 10_000_000
    const val ARGON2_MIN_M = 19_456
    const val ARGON2_MIN_T = 2
    val ARGON2_DEFAULT = Triple(65_536, 3, 1)
    val ARGON2_STRONG = Triple(131_072, 4, 1)

    private const val AES_TAG_BITS = 128

    object Aad {
        fun slot(vaultId: String, slotId: String) = "luciverse/pevv/v1/slot/$vaultId/$slotId"
        fun entry(vaultId: String, entryId: String, ver: Long) = "luciverse/pevv/v1/entry/$vaultId/$entryId/$ver"
        fun meta(vaultId: String, rev: Long) = "luciverse/pevv/v1/meta/$vaultId/$rev"
        fun totp(vaultId: String) = "luciverse/pevv/v1/totp/$vaultId"
        fun export(id: String) = "luciverse/pevv/v1/export/$id"
        fun kit(vaultId: String) = "luciverse/pevv/v1/kit/$vaultId"
    }

    const val INFO_PASSWORD = "luciverse/pevv/v1/password-kek"
    const val INFO_PRF = "luciverse/pevv/v1/prf-kek"
    const val INFO_RECOVERY_CODE = "luciverse/pevv/v1/recovery-code-kek"
    const val INFO_RECOVERY_KEY = "luciverse/pevv/v1/recovery-key-kek"
    const val INFO_USB = "luciverse/pevv/v1/usb-kek"
    const val TAG_USB_GATE = "luciverse/pevv/v1/usb-gate"

    fun validateKdf(k: Kdf) {
        require(unb64(k.salt).size >= 16) { "KDF salt must be at least 16 bytes" }
        when (k) {
            is Kdf.Argon2id -> {
                require(k.m in ARGON2_MIN_M..1_048_576) { "Argon2id memory out of range" }
                require(k.t in ARGON2_MIN_T..20) { "Argon2id iterations out of range" }
                require(k.p in 1..4) { "Argon2id parallelism out of range" }
            }
            is Kdf.Pbkdf2 -> require(k.iter in PBKDF2_MIN_ITER..PBKDF2_MAX_ITER) { "PBKDF2 iterations must be at least $PBKDF2_MIN_ITER" }
        }
    }

    fun newKdf(strong: Boolean = false, forcePbkdf2: Boolean = false): Kdf {
        val salt = b64(Bytes.random(16))
        if (forcePbkdf2) return Kdf.Pbkdf2(if (strong) 1_200_000 else PBKDF2_MIN_ITER, salt)
        val (m, t, p) = if (strong) ARGON2_STRONG else ARGON2_DEFAULT
        return Kdf.Argon2id(m, t, p, salt)
    }

    /** Passwords are NFC-normalised so one passphrase unlocks on every device and keyboard. */
    fun normalizePassword(pw: String): String = Normalizer.normalize(pw, Normalizer.Form.NFC)

    /** Stretch a password into 32 raw bytes (the caller wipes). */
    fun stretch(password: String, k: Kdf): ByteArray {
        validateKdf(k)
        val pw = normalizePassword(password)
        require(pw.isNotEmpty()) { "empty password" }
        val salt = unb64(k.salt)
        val out = ByteArray(32)
        when (k) {
            is Kdf.Argon2id -> {
                val params = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                    .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                    .withIterations(k.t).withMemoryAsKB(k.m).withParallelism(k.p).withSalt(salt).build()
                val gen = Argon2BytesGenerator()
                gen.init(params)
                gen.generateBytes(utf8(pw), out, 0, out.size)
            }
            is Kdf.Pbkdf2 -> {
                val g = PKCS5S2ParametersGenerator(SHA256Digest())
                g.init(utf8(pw), salt, k.iter)
                (g.generateDerivedParameters(256) as KeyParameter).key.copyInto(out)
            }
        }
        return out
    }

    private fun hmac(alg: String, key: ByteArray, vararg data: ByteArray): ByteArray {
        val mac = Mac.getInstance(alg)
        mac.init(SecretKeySpec(key, alg))
        for (d in data) mac.update(d)
        return mac.doFinal()
    }

    fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray = hmac("HmacSHA256", key, data)

    /** HKDF-SHA256, 32 bytes out (RFC 5869). An empty salt is a block of zeros, like WebCrypto. */
    fun hkdf(ikm: ByteArray, salt: ByteArray, info: String): ByteArray {
        val prk = hmac("HmacSHA256", if (salt.isEmpty()) ByteArray(32) else salt, ikm)
        return hmac("HmacSHA256", prk, utf8(info), byteArrayOf(1))
    }

    fun sha256(vararg data: ByteArray): ByteArray {
        val md = MessageDigest.getInstance("SHA-256")
        for (d in data) md.update(d)
        return md.digest()
    }

    /** KEK (32 raw bytes) from a password: stretch, then domain-separate with HKDF using the KDF salt. */
    fun passwordKek(password: String, k: Kdf): ByteArray {
        val raw = stretch(password, k)
        try {
            return hkdf(raw, unb64(k.salt), INFO_PASSWORD)
        } finally {
            Bytes.wipe(raw)
        }
    }

    fun seal(key: ByteArray, plain: ByteArray, aad: String): Sealed {
        require(key.size == 32) { "key must be 256 bits" }
        val iv = Bytes.random(12)
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(AES_TAG_BITS, iv))
        c.updateAAD(utf8(aad))
        return Sealed(b64(iv), b64(c.doFinal(plain)))
    }

    fun open(key: ByteArray, s: Sealed, aad: String): ByteArray {
        val iv: ByteArray
        val ct: ByteArray
        try {
            iv = unb64(s.iv)
            ct = unb64(s.ct)
        } catch (_: IllegalArgumentException) {
            throw DecryptError("damaged record")
        }
        if (iv.size != 12 || ct.size < 16) throw DecryptError("damaged record")
        try {
            val c = Cipher.getInstance("AES/GCM/NoPadding")
            c.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(AES_TAG_BITS, iv))
            c.updateAAD(utf8(aad))
            return c.doFinal(ct)
        } catch (_: java.security.GeneralSecurityException) {
            throw DecryptError()
        }
    }

    fun sealJson(key: ByteArray, value: JsonElement, aad: String): Sealed = seal(key, utf8(Json.encode(value)), aad)

    fun openJson(key: ByteArray, s: Sealed, aad: String): JsonElement {
        val pt = open(key, s, aad)
        try {
            return Json.parse(Bytes.fromUtf8(pt))
        } catch (_: Exception) {
            throw DecryptError("damaged record")
        } finally {
            Bytes.wipe(pt)
        }
    }

    fun newVaultKey(): ByteArray = Bytes.random(32)

    fun wrapVaultKey(kek: ByteArray, vaultKey: ByteArray, vaultId: String, slotId: String): Sealed =
        seal(kek, vaultKey, Aad.slot(vaultId, slotId))

    fun unwrapVaultKey(kek: ByteArray, wrapped: Sealed, vaultId: String, slotId: String): ByteArray {
        val raw = open(kek, wrapped, Aad.slot(vaultId, slotId))
        if (raw.size != 32) {
            Bytes.wipe(raw)
            throw DecryptError("damaged key slot")
        }
        return raw
    }
}
