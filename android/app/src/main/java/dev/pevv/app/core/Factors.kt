package dev.pevv.app.core

import dev.pevv.app.core.Bytes.b64
import dev.pevv.app.core.Bytes.unb64
import dev.pevv.app.core.Bytes.utf8
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.net.URLDecoder
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/** Recovery codes, the recovery key and the recovery kit. A port of src/pevv/recovery.ts. */
object Recovery {
    const val COUNT = 10

    /** XXXXX-XXXXX-XXXXX-XXXXX (20 base32 characters = 100 bits). */
    fun newRecoveryCode(): String = Bytes.base32Encode(Bytes.random(13)).take(20).chunked(5).joinToString("-")

    fun normalizeCode(code: String): String = code.uppercase().replace(Regex("[^A-Z2-7]"), "")

    fun isWellFormedCode(code: String) = normalizeCode(code).length == 20

    fun codeHash(code: String, salt: String): String = b64(Crypto.sha256(unb64(salt), utf8(normalizeCode(code))))

    fun codeKek(code: String, salt: String): ByteArray = Crypto.hkdf(utf8(normalizeCode(code)), unb64(salt), Crypto.INFO_RECOVERY_CODE)

    /** 32 random bytes as 13 groups of 4 base32 characters (the last group has 4). */
    fun newRecoveryKey(): String = Bytes.base32Encode(Bytes.random(32)).chunked(4).joinToString("-")

    fun recoveryKeyBytes(key: String): ByteArray {
        val b = Bytes.base32Decode(key)
        require(b.size == 32) { "recovery key must be 52 base32 characters" }
        return b
    }

    fun recoveryKeyKek(key: String, salt: String): ByteArray = Crypto.hkdf(recoveryKeyBytes(key), unb64(salt), Crypto.INFO_RECOVERY_KEY)

    fun buildKit(vaultId: String, recoveryKey: String, passphrase: String, kdf: Kdf? = null, created: String = java.time.Instant.now().toString()): JsonObject {
        val params = kdf ?: Crypto.newKdf()
        val kek = Crypto.passwordKek(passphrase, params)
        val sealed = Crypto.sealJson(kek, buildJsonObject { put("recoveryKey", recoveryKey) }, Crypto.Aad.kit(vaultId))
        Bytes.wipe(kek)
        return buildJsonObject {
            put("format", "luciverse.pevv.recovery-kit"); put("v", 1); put("vaultId", vaultId); put("created", created)
            put("kdf", params.toJson()); put("sealed", sealed.toJson())
            put("note", "PEVV recovery kit. Open PEVV → Locked → Use recovery kit, choose this file and enter the kit passphrase. Keep it offline.")
        }
    }

    fun openKit(text: String, passphrase: String): String {
        val kit = Json.parseObject(text)
        require(kit.str("format") == "luciverse.pevv.recovery-kit" && kit.long("v") == 1L) { "not a PEVV recovery kit" }
        val vaultId = kit.str("vaultId") ?: throw IllegalArgumentException("not a PEVV recovery kit")
        val kek = Crypto.passwordKek(passphrase, Kdf.from(kit["kdf"]))
        try {
            val o = Crypto.openJson(kek, Sealed.from(kit["sealed"]), Crypto.Aad.kit(vaultId)) as JsonObject
            val key = o.str("recoveryKey") ?: throw DecryptError()
            recoveryKeyBytes(key)
            return key
        } finally {
            Bytes.wipe(kek)
        }
    }
}

/** The `.pevvkey` file (src/pevv/usbkey.ts). */
object UsbKeyFile {
    const val FORMAT = "luciverse.pevvkey"
    const val FILE_NAME = ".pevvkey"
    const val KEY_BYTES = 32

    class Created(val text: String, val secret: ByteArray)

    fun create(vaultId: String): Created {
        val secret = Bytes.random(KEY_BYTES)
        val file = buildJsonObject { put("format", FORMAT); put("v", 1); put("vault", vaultId); put("secret", b64(secret)) }
        return Created(Json.encodePretty(file) + "\n", secret)
    }

    /** Returns the vault hint and the secret, or throws a plain-language error. */
    fun parse(text: String): Pair<String, ByteArray> {
        val j = try { Json.parseObject(text) } catch (_: Exception) { null }
        if (j == null || j.str("format") != FORMAT || j.long("v") != 1L || j.str("secret") == null || j.str("vault") == null) {
            throw IllegalArgumentException("That is not a PEVV key file.")
        }
        val secret = try { unb64(j.str("secret")!!) } catch (_: IllegalArgumentException) { throw IllegalArgumentException("That key file is damaged.") }
        if (secret.size != KEY_BYTES) throw IllegalArgumentException("That key file is damaged.")
        return j.str("vault")!! to secret
    }

    fun gateCheck(secret: ByteArray): String = b64(Crypto.sha256(utf8(Crypto.TAG_USB_GATE), secret))

    fun gateMatches(secret: ByteArray, check: String): Boolean = try {
        Bytes.ctEqual(unb64(gateCheck(secret)), unb64(check))
    } catch (_: IllegalArgumentException) {
        false
    }
}

/** The authenticator secret and settings (src/pevv/totp.ts). */
data class TotpConfig(val secret: String, val digits: Int? = null, val period: Int? = null, val algorithm: String? = null) {
    fun toJson(): JsonObject = buildJsonObject {
        put("secret", secret)
        digits?.let { put("digits", it) }
        period?.let { put("period", it) }
        algorithm?.let { put("algorithm", it) }
    }

    companion object {
        fun from(e: JsonElement): TotpConfig {
            val o = e as? JsonObject ?: throw DecryptError("damaged record")
            return TotpConfig(o.str("secret") ?: throw DecryptError("damaged record"), o.int("digits"), o.int("period"), o.str("algorithm"))
        }
    }
}

object Totp {
    fun newSecret(bytes: Int = 20): String = Bytes.base32Encode(Bytes.random(bytes))

    private fun macName(alg: String) = when (alg) { "SHA-256" -> "HmacSHA256"; "SHA-512" -> "HmacSHA512"; else -> "HmacSHA1" }

    fun hotp(secret: ByteArray, counter: Long, digits: Int = 6, algorithm: String = "SHA-1"): String {
        require(counter >= 0) { "bad counter" }
        val msg = ByteArray(8)
        var c = counter
        for (i in 7 downTo 0) {
            msg[i] = (c and 0xff).toByte()
            c = c ushr 8
        }
        val name = macName(algorithm)
        val mac = Mac.getInstance(name).also { it.init(SecretKeySpec(secret, name)) }.doFinal(msg)
        val off = mac[mac.size - 1].toInt() and 0x0f
        val bin = ((mac[off].toInt() and 0x7f) shl 24) or ((mac[off + 1].toInt() and 0xff) shl 16) or
            ((mac[off + 2].toInt() and 0xff) shl 8) or (mac[off + 3].toInt() and 0xff)
        var mod = 1L
        repeat(digits) { mod *= 10 }
        return (bin.toLong() % mod).toString().padStart(digits, '0')
    }

    fun totpAt(cfg: TotpConfig, unixMs: Long): String {
        val period = cfg.period ?: 30
        return hotp(Bytes.base32Decode(cfg.secret), unixMs / 1000 / period, cfg.digits ?: 6, cfg.algorithm ?: "SHA-1")
    }

    fun secondsLeft(cfg: TotpConfig, unixMs: Long): Int {
        val period = cfg.period ?: 30
        return period - ((unixMs / 1000) % period).toInt()
    }

    /** Matched step or null; rejects reuse via `lastStep`. */
    fun verify(cfg: TotpConfig, code: String, unixMs: Long = System.currentTimeMillis(), window: Int = 1, lastStep: Long? = null): Long? {
        val clean = code.replace(Regex("\\s"), "")
        val digits = cfg.digits ?: 6
        if (!Regex("^\\d{$digits}$").matches(clean)) return null
        val period = cfg.period ?: 30
        val step = unixMs / 1000 / period
        val key = Bytes.base32Decode(cfg.secret)
        var match: Long? = null
        for (w in -window..window) {
            val s = step + w
            if (s < 0) continue
            val want = hotp(key, s, digits, cfg.algorithm ?: "SHA-1")
            if (java.security.MessageDigest.isEqual(utf8(want), utf8(clean)) && match == null) match = s
        }
        if (match != null && lastStep != null && match <= lastStep) return null
        return match
    }

    /** An otpauth://totp URI or a bare base32 secret (a login's 2FA field). */
    fun parse(input: String): TotpConfig {
        val s = input.trim()
        if (!s.lowercase().startsWith("otpauth://")) {
            Bytes.base32Decode(s)
            return TotpConfig(s.replace(Regex("[\\s=-]"), "").uppercase())
        }
        val rest = s.substring("otpauth://".length)
        val host = rest.substringBefore('/').lowercase()
        require(host == "totp") { "only TOTP is supported" }
        val q = rest.substringAfter('?', "").split('&').filter { it.isNotEmpty() }.associate {
            val k = URLDecoder.decode(it.substringBefore('='), "UTF-8")
            k to URLDecoder.decode(it.substringAfter('=', ""), "UTF-8")
        }
        val secret = (q["secret"] ?: "").replace(Regex("[\\s=]"), "").uppercase()
        Bytes.base32Decode(secret)
        require(secret.isNotEmpty()) { "missing secret" }
        val algorithm = when ((q["algorithm"] ?: "SHA1").uppercase()) { "SHA256" -> "SHA-256"; "SHA512" -> "SHA-512"; else -> "SHA-1" }
        val digits = (q["digits"] ?: "6").toIntOrNull() ?: 0
        val period = (q["period"] ?: "30").toIntOrNull() ?: 0
        require(digits in 6..8) { "digits must be 6-8" }
        require(period in 5..300) { "bad period" }
        return TotpConfig(secret, digits, period, algorithm)
    }

    /** otpauth URI for showing a QR of the vault's own second factor. */
    fun otpauthUri(cfg: TotpConfig, account: String, issuer: String = "PEVV"): String {
        val label = java.net.URLEncoder.encode("$issuer:$account", "UTF-8").replace("+", "%20")
        val sb = StringBuilder("otpauth://totp/$label?secret=${cfg.secret}&issuer=${java.net.URLEncoder.encode(issuer, "UTF-8")}")
        if (cfg.algorithm != null && cfg.algorithm != "SHA-1") sb.append("&algorithm=").append(cfg.algorithm.replace("-", ""))
        if (cfg.digits != null && cfg.digits != 6) sb.append("&digits=").append(cfg.digits)
        if (cfg.period != null && cfg.period != 30) sb.append("&period=").append(cfg.period)
        return sb.toString()
    }

    /** Attempt limiter: 5 free tries, then a lock-out of 30 s doubling up to 1 h. */
    fun limiterDelay(fails: Int): Long = if (fails < 5) 0 else minOf(3_600_000L, 30_000L shl minOf(fails - 5, 20))
}
