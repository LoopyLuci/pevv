package dev.pevv.app.core

import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.LuminanceSource
import com.google.zxing.MultiFormatReader
import com.google.zxing.RGBLuminanceSource
import com.google.zxing.common.GlobalHistogramBinarizer
import com.google.zxing.common.HybridBinarizer

/**
 * The pure, on-device part of QR scanning (ZXing core only, no Android types), so it is unit-tested on the JVM.
 * One instance per thread: [MultiFormatReader] keeps state between calls.
 */
class QrReader {
    private val reader = MultiFormatReader().also {
        it.setHints(mapOf(DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE), DecodeHintType.TRY_HARDER to true))
    }

    /**
     * The text of the first QR code found, or null. The quick pass is one normal read. [thorough] also tries
     * the inverted image (light code on a dark background) and a global-histogram binarizer (low-contrast or
     * unevenly lit codes), which cost more, so a live camera only asks for them on some frames.
     */
    fun decode(source: LuminanceSource, thorough: Boolean = true): String? {
        val attempts = ArrayList<() -> BinaryBitmap>(4)
        attempts += { BinaryBitmap(HybridBinarizer(source)) }
        if (thorough) {
            attempts += { BinaryBitmap(GlobalHistogramBinarizer(source)) }
            attempts += { BinaryBitmap(HybridBinarizer(source.invert())) }
            attempts += { BinaryBitmap(GlobalHistogramBinarizer(source.invert())) }
        }
        for (make in attempts) {
            try {
                val text = reader.decodeWithState(make()).text
                if (!text.isNullOrBlank()) return text
            } catch (_: Exception) {
                // NotFound / Checksum / Format: no readable code in this attempt.
            } finally {
                reader.reset()
            }
        }
        return null
    }

    /** Decodes ARGB pixels (a picked photo or a bitmap). */
    fun decodeArgb(width: Int, height: Int, pixels: IntArray, thorough: Boolean = true): String? =
        decode(RGBLuminanceSource(width, height, pixels), thorough)
}

/**
 * Drops a repeat of the same text inside [windowMs]. A different text always passes at once, and the same text
 * passes again after the window, because cycling transfer frames have to be able to repeat.
 */
class QrDebounce(private val windowMs: Long = 1500) {
    private var lastText: String? = null
    private var lastAt = 0L

    @Synchronized
    fun accept(text: String, nowMs: Long): Boolean {
        if (text == lastText && nowMs - lastAt <= windowMs) return false
        lastText = text
        lastAt = nowMs
        return true
    }

    @Synchronized
    fun reset() { lastText = null; lastAt = 0L }
}

/**
 * How every QR the app shows is drawn: error correction M, the lowest version the text needs (ZXing picks the
 * densest-fitting mode and version), a quiet zone of [MARGIN] modules, pure black on pure white.
 */
object QrEncode {
    const val MARGIN = 4

    private fun code(text: String): com.google.zxing.qrcode.encoder.QRCode {
        // No character-set hint for plain ASCII: the hint adds an ECI header that wastes space and some readers dislike.
        val hints = if (text.all { it.code < 128 }) emptyMap() else mapOf(com.google.zxing.EncodeHintType.CHARACTER_SET to "UTF-8")
        return com.google.zxing.qrcode.encoder.Encoder.encode(text, com.google.zxing.qrcode.decoder.ErrorCorrectionLevel.M, hints)
    }

    fun version(text: String): Int = code(text).version.versionNumber

    /** Side in pixels and ARGB pixels (opaque black / white) at the largest whole-pixel module size within [targetPx]. */
    fun render(text: String, targetPx: Int): Pair<Int, IntArray> {
        val m = code(text).matrix
        val modules = m.width + 2 * MARGIN
        val scale = maxOf(1, targetPx / modules)
        val side = modules * scale
        val px = IntArray(side * side) { i ->
            val mx = i % side / scale - MARGIN
            val my = i / side / scale - MARGIN
            if (mx in 0 until m.width && my in 0 until m.height && m.get(mx, my).toInt() == 1) 0xFF000000.toInt() else 0xFFFFFFFF.toInt()
        }
        return side to px
    }
}
