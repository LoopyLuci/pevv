package dev.pevv.app.core

import java.security.SecureRandom
import java.util.Base64

/** Byte helpers. Mirrors src/pevv/bytes.ts (standard and URL-safe base64, RFC 4648 base32). */
object Bytes {
    private val rng = SecureRandom()
    private const val B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

    fun random(n: Int): ByteArray = ByteArray(n).also { rng.nextBytes(it) }

    fun b64(b: ByteArray): String = Base64.getEncoder().encodeToString(b)

    /** Like `atob`: padding is optional. */
    fun unb64(s: String): ByteArray = Base64.getDecoder().decode(s)

    fun b64url(b: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(b)

    fun unb64url(s: String): ByteArray = Base64.getUrlDecoder().decode(s)

    fun utf8(s: String): ByteArray = s.toByteArray(Charsets.UTF_8)

    fun fromUtf8(b: ByteArray): String = String(b, Charsets.UTF_8)

    fun hex(b: ByteArray): String = b.joinToString("") { "%02x".format(it) }

    fun unhex(s: String): ByteArray = ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    fun concat(vararg parts: ByteArray): ByteArray {
        val out = ByteArray(parts.sumOf { it.size })
        var o = 0
        for (p in parts) {
            p.copyInto(out, o)
            o += p.size
        }
        return out
    }

    /** Constant-time equality. */
    fun ctEqual(a: ByteArray, b: ByteArray): Boolean {
        if (a.size != b.size) return false
        var d = 0
        for (i in a.indices) d = d or (a[i].toInt() xor b[i].toInt())
        return d == 0
    }

    fun wipe(b: ByteArray?) {
        b?.fill(0)
    }

    fun base32Encode(bytes: ByteArray): String {
        var bits = 0
        var value = 0
        val out = StringBuilder()
        for (byte in bytes) {
            value = (value shl 8) or (byte.toInt() and 0xff)
            bits += 8
            while (bits >= 5) {
                out.append(B32[(value ushr (bits - 5)) and 31])
                bits -= 5
            }
            value = value and ((1 shl bits) - 1)
        }
        if (bits > 0) out.append(B32[(value shl (5 - bits)) and 31])
        return out.toString()
    }

    fun base32Decode(input: String): ByteArray {
        val s = input.uppercase().replace(Regex("[\\s=-]"), "")
        require(s.all { it in B32 }) { "invalid base32" }
        var bits = 0
        var value = 0
        val out = ArrayList<Byte>()
        for (c in s) {
            value = (value shl 5) or B32.indexOf(c)
            bits += 5
            if (bits >= 8) {
                out.add(((value ushr (bits - 8)) and 255).toByte())
                bits -= 8
                value = value and ((1 shl bits) - 1)
            }
        }
        return out.toByteArray()
    }
}
