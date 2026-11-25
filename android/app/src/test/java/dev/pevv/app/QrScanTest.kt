package dev.pevv.app

import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import dev.pevv.app.core.QrDebounce
import dev.pevv.app.core.QrReader
import dev.pevv.app.core.Transfer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class QrScanTest {
    /** ARGB pixels of a QR with a quiet zone; [dark]/[light] are the module and background colours. */
    private fun qr(text: String, dark: Int = 0xFF000000.toInt(), light: Int = 0xFFFFFFFF.toInt(), scale: Int = 6): Triple<Int, Int, IntArray> {
        val m = QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, 0, 0, mapOf(EncodeHintType.MARGIN to 4))
        val w = m.width * scale
        val h = m.height * scale
        val px = IntArray(w * h) { i -> if (m.get(i % w / scale, i / w / scale)) dark else light }
        return Triple(w, h, px)
    }

    @Test fun readsANormalCode() {
        val (w, h, px) = qr("hello pevv")
        assertEquals("hello pevv", QrReader().decodeArgb(w, h, px, thorough = false))
    }

    @Test fun readsAnInvertedCodeOnlyInThoroughMode() {
        val (w, h, px) = qr("inverted", dark = 0xFFFFFFFF.toInt(), light = 0xFF000000.toInt())
        assertNull(QrReader().decodeArgb(w, h, px, thorough = false))
        assertEquals("inverted", QrReader().decodeArgb(w, h, px, thorough = true))
    }

    @Test fun readsALowContrastCode() {
        val (w, h, px) = qr("faint", dark = 0xFF8C8C8C.toInt(), light = 0xFFB4B4B4.toInt())
        assertEquals("faint", QrReader().decodeArgb(w, h, px, thorough = true))
    }

    @Test fun blankImageGivesNull() {
        val px = IntArray(100 * 100) { 0xFFFFFFFF.toInt() }
        assertNull(QrReader().decodeArgb(100, 100, px))
    }

    @Test fun readerIsReusableAfterAMiss() {
        val r = QrReader()
        assertNull(r.decodeArgb(50, 50, IntArray(2500) { 0xFF000000.toInt() }))
        val (w, h, px) = qr("again")
        assertEquals("again", r.decodeArgb(w, h, px))
    }

    @Test fun decodedVaultTokenParses() {
        val token = "H." + "a".repeat(43) + "." + "b".repeat(22)
        val (w, h, px) = qr("https://example.invalid/app?pevvq=$token#x")
        val text = QrReader().decodeArgb(w, h, px)
        assertNotNull(text)
        assertTrue(Transfer.parseScan(text!!) is Transfer.ScanHit.HandoffHit)
        assertNull(Transfer.parseScan("not a pevv code"))
    }

    @Test fun debounceDropsRepeatsInsideTheWindow() {
        val d = QrDebounce(1000)
        assertTrue(d.accept("a", 0))
        assertFalse(d.accept("a", 500))
        assertFalse(d.accept("a", 1000))
        assertTrue(d.accept("a", 1001))
    }

    @Test fun debounceLetsADifferentTextThrough() {
        val d = QrDebounce(1000)
        assertTrue(d.accept("a", 0))
        assertTrue(d.accept("b", 10))
        assertTrue(d.accept("a", 20))
        d.reset()
        assertTrue(d.accept("a", 30))
    }
}
