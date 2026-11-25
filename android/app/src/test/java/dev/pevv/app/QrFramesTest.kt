package dev.pevv.app

import dev.pevv.app.core.QrEncode
import dev.pevv.app.core.QrReader
import dev.pevv.app.core.Transfer
import dev.pevv.app.core.TransferError
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/** The same vectors as tests/unit/pevv.qr.test.ts: both sides must cut, collect and size QR frames the same way. */
class QrFramesTest {
    private val v = Vectors.obj("qr-frames")

    @Test fun usesTheVectorConstants() {
        assertEquals(v["chunk"]!!.l().toInt(), Transfer.FRAME_CHUNK)
        assertEquals(v["maxFrames"]!!.l().toInt(), Transfer.MAX_FRAMES)
        assertEquals(v["maxVersion"]!!.l().toInt(), Transfer.MAX_FRAME_VERSION)
        assertTrue(QrEncode.MARGIN >= 4)
    }

    @Test fun cutsDataIntoTheSameFrames() {
        for (c in v["split"]!!.a()) {
            val o = c.o()
            assertEquals(o["frames"]!!.a().map { it.s() }, Transfer.splitFrames(o["data"]!!.s(), o["crc"]!!.s()))
        }
        try {
            Transfer.splitFrames("x".repeat(Transfer.FRAME_CHUNK * Transfer.MAX_FRAMES + 1), "aaaaaaaa")
            fail("expected qr-too-big")
        } catch (e: TransferError) {
            assertEquals("qr-too-big", e.code)
        }
    }

    @Test fun collectsFramesInAnyOrderAndDropsAStaleSet() {
        for (c in v["assemble"]!!.a()) {
            val o = c.o()
            val frames = mutableListOf<String>()
            val got = o["input"]!!.a().map { raw -> Transfer.addFrame(frames, raw.s())?.let { listOf(it.got, it.need) } }
            val want = o["progress"]!!.a().map { p -> if (p is kotlinx.serialization.json.JsonNull) null else p.a().map { it.l().toInt() } }
            assertEquals(o["name"]!!.s(), want, got)
        }
    }

    @Test fun everySplitVectorReassemblesComplete() {
        for (c in v["split"]!!.a()) {
            val frames = c.o()["frames"]!!.a().map { it.s() }
            val list = mutableListOf<String>()
            var last: Transfer.FrameProgress? = null
            for (f in frames.reversed()) last = Transfer.addFrame(list, f)
            assertTrue(last!!.complete)
            assertEquals(frames.size, list.size)
        }
    }

    @Test fun picksTheLowestVersionAndKeepsFramesScannable() {
        for (c in v["versions"]!!.a()) {
            val o = c.o()
            assertEquals(o["text"]!!.s(), o["version"]!!.l().toInt(), QrEncode.version(o["text"]!!.s()))
        }
        for (c in v["split"]!!.a()) for (f in c.o()["frames"]!!.a()) assertTrue(QrEncode.version(f.s()) <= Transfer.MAX_FRAME_VERSION)
    }

    @Test fun drawnCodeHasAQuietZoneAndReadsBack() {
        val text = v["split"]!!.a()[5].o()["frames"]!!.a()[0].s()
        val (side, px) = QrEncode.render(text, 1024)
        val scale = side / (QrEncode.version(text) * 4 + 17 + 2 * QrEncode.MARGIN)
        // The border (4 modules) is pure white on every side, and every pixel is pure black or white.
        val border = QrEncode.MARGIN * scale
        for (y in 0 until side) for (x in 0 until side) {
            val p = px[y * side + x]
            assertTrue(p == 0xFF000000.toInt() || p == 0xFFFFFFFF.toInt())
            if (x < border || y < border || x >= side - border || y >= side - border) assertEquals(0xFFFFFFFF.toInt(), p)
        }
        assertEquals(text, QrReader().decodeArgb(side, side, px, thorough = false))
        assertNotNull(Transfer.parseFrame(text))
        assertNull(Transfer.addFrame(mutableListOf(), "not a frame"))
    }
}
