package dev.pevv.app.core

import dev.pevv.app.core.Bytes.b64
import dev.pevv.app.core.Bytes.b64url
import dev.pevv.app.core.Bytes.unb64
import dev.pevv.app.core.Bytes.unb64url
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.net.URLDecoder
import java.net.URLEncoder
import java.util.zip.GZIPInputStream
import java.util.zip.GZIPOutputStream
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** Errors carry the same stable codes as the web app (`qr-expired`, `qr-damaged`, ...). The UI maps them to text. */
class TransferError(val code: String) : Exception(code)

/** Vault transfer by QR: the handoff envelope and the offline `PEVV1|...` frames (src/pevv/qr.ts). */
object Transfer {
    const val HANDOFF_TTL_MS = 3 * 60 * 1000L
    const val QR_HOLD_MS = 10 * 60 * 1000L
    const val HANDOFF_PATH = "/vault/pevv-handoff.json"
    private const val CHUNK = 520
    private const val MAX_FRAMES = 12

    class Handoff(val key: String, val envelope: JsonObject)

    fun sealHandoff(json: String, now: Long = System.currentTimeMillis(), ttl: Long = HANDOFF_TTL_MS): Handoff {
        val raw = Bytes.random(32)
        val iv = Bytes.random(12)
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(raw, "AES"), GCMParameterSpec(128, iv))
        val ct = c.doFinal(Bytes.utf8(json))
        val env = buildJsonObject { put("v", 1); put("exp", now + ttl); put("iv", b64(iv)); put("ct", b64(ct)) }
        return Handoff(b64url(raw), env)
    }

    fun openHandoff(envelope: JsonObject, keyB64: String, now: Long = System.currentTimeMillis()): String {
        val exp = envelope.long("exp")
        if (envelope.long("v") != 1L || exp == null || now > exp) throw TransferError("qr-expired")
        try {
            val c = Cipher.getInstance("AES/GCM/NoPadding")
            c.init(Cipher.DECRYPT_MODE, SecretKeySpec(unb64url(keyB64), "AES"), GCMParameterSpec(128, unb64(envelope.str("iv")!!)))
            return Bytes.fromUtf8(c.doFinal(unb64(envelope.str("ct")!!)))
        } catch (_: Exception) {
            throw TransferError("qr-damaged")
        }
    }

    private fun sha8(b: ByteArray): String = Bytes.hex(Crypto.sha256(b)).take(8)

    fun gzip(data: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        GZIPOutputStream(out).use { it.write(data) }
        return out.toByteArray()
    }

    fun gunzip(data: ByteArray): ByteArray = GZIPInputStream(ByteArrayInputStream(data)).use { it.readBytes() }

    fun packVault(file: VaultFile): List<String> {
        VaultFile.validate(file)
        val gz = gzip(Bytes.utf8(file.toText()))
        val data = b64url(gz)
        val crc = sha8(gz)
        val n = maxOf(1, (data.length + CHUNK - 1) / CHUNK)
        if (n > MAX_FRAMES) throw TransferError("qr-too-big")
        return (0 until n).map { i -> "PEVV1|$i|$n|$crc|${data.substring(i * CHUNK, minOf(data.length, (i + 1) * CHUNK))}" }
    }

    private val FRAME = Regex("^PEVV1\\|(\\d+)\\|(\\d+)\\|([0-9a-f]{8})\\|([A-Za-z0-9_-]*)$")

    class Frame(val i: Int, val n: Int, val crc: String, val chunk: String)

    fun parseFrame(text: String): Frame? {
        val m = FRAME.matchEntire(text.trim()) ?: return null
        val i = m.groupValues[1].toIntOrNull() ?: return null
        val n = m.groupValues[2].toIntOrNull() ?: return null
        if (n < 1 || n > MAX_FRAMES || i < 0 || i >= n) return null
        return Frame(i, n, m.groupValues[3], m.groupValues[4])
    }

    fun unpackFrames(frames: List<String>): VaultFile {
        val parts = LinkedHashMap<Int, Frame>()
        for (raw in frames) {
            val p = parseFrame(raw) ?: throw TransferError("qr-damaged")
            parts[p.i] = p
        }
        val first = parts.values.firstOrNull()
        if (first == null || parts.size != first.n) throw TransferError("qr-incomplete")
        val data = StringBuilder()
        for (i in 0 until first.n) {
            val p = parts[i]
            if (p == null || p.n != first.n || p.crc != first.crc) throw TransferError("qr-damaged")
            data.append(p.chunk)
        }
        val gz = try { unb64url(data.toString()) } catch (_: IllegalArgumentException) { throw TransferError("qr-damaged") }
        if (sha8(gz) != first.crc) throw TransferError("qr-damaged")
        try {
            return VaultFile.parse(Bytes.fromUtf8(gunzip(gz)))
        } catch (_: Exception) {
            throw TransferError("qr-damaged")
        }
    }

    sealed class ScanHit {
        class HandoffHit(val key: String, val xfer: String?) : ScanHit()
        class FrameHit(val frame: String) : ScanHit()
    }

    /** Accepts a raw code or a PEVV web-app URL whose query or hash carries `pevvq=...`. */
    fun parseScan(text: String): ScanHit? {
        var token = text.trim()
        val at = token.indexOf("pevvq=")
        if (at >= 0) {
            token = token.substring(at + 6).substringBefore('&').substringBefore('#')
            token = try { URLDecoder.decode(token.replace("+", "%2B"), "UTF-8") } catch (_: Exception) { token }
        }
        if (token.startsWith("H.")) {
            val rest = token.substring(2)
            val dot = rest.indexOf('.')
            val key = if (dot < 0) rest else rest.substring(0, dot)
            val xfer = if (dot < 0) "" else rest.substring(dot + 1)
            if (!Regex("^[A-Za-z0-9_-]{20,}$").matches(key)) return null
            if (xfer.isNotEmpty() && !Regex("^[A-Za-z0-9_-]{16,80}$").matches(xfer)) return null
            return ScanHit.HandoffHit(key, xfer.ifEmpty { null })
        }
        if (parseFrame(token) != null) return ScanHit.FrameHit(token)
        return null
    }

    /** What the QR carries for a live transfer: a link another phone can open when the build has a public URL, else the bare code. */
    fun shareUrl(token: String, base: String?): String {
        if (base.isNullOrEmpty()) return token
        val noHash = base.substringBefore('#')
        val q = "pevvq=" + URLEncoder.encode(token, "UTF-8").replace("+", "%20")
        return "$noHash${if (noHash.contains('?')) "&" else "?"}$q#$q"
    }

    fun newTransferToken(): String = b64url(Bytes.random(16))

    fun relayTopic(token: String) = "pevv:$token"

    fun rosterTopic(vaultId: String) = "pevv:d:$vaultId"

    /** Live transfer frame size (host/relay.ts FRAME). */
    const val RELAY_FRAME = 48_000

    fun splitBody(body: String, frame: Int = RELAY_FRAME): List<String> {
        if (body.isEmpty()) return listOf("")
        return body.chunked(frame)
    }
}
