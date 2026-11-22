package dev.pevv.app.sync

import dev.pevv.app.core.Transfer
import dev.pevv.app.core.long
import dev.pevv.app.core.str
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.util.concurrent.ConcurrentHashMap

class Pulled(val got: Int, val total: Int, val body: String?)

/**
 * The live lane for a vault move and for the device roster: the same `pevv:*` broadcast topics and event names as
 * src/pevv/host/relay.ts, so the web app, the extension, the desktop app and this app talk to each other.
 * Needs the sync config (the relay uses its own anonymous session); without it every call fails with `qr-nosync`.
 */
class Relay(private val auth: Supabase) {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val socket by lazy { RealtimeSocket { try { auth.relayToken() } catch (_: SyncError) { null } } }

    private class Sender(val ch: RealtimeSocket.Channel, val job: Job)

    private val senders = ConcurrentHashMap<String, Sender>()

    /** Keep sending until the QR is closed, so a late scan still receives the vault. */
    suspend fun putTransfer(token: String, body: String, onProgress: (Int, Int) -> Unit = { _, _ -> }) {
        if (!SyncConfig.configured) throw SyncError("qr-nosync")
        val parts = Transfer.splitBody(body)
        val total = parts.size
        onProgress(0, total)
        var busy = false
        lateinit var ch: RealtimeSocket.Channel
        fun flush() {
            if (busy) return
            busy = true
            try {
                for (seq in 0 until total) {
                    if (!ch.send("part", buildJsonObject { put("seq", seq); put("total", total); put("body", parts[seq]) })) return
                }
            } finally { busy = false }
        }
        ch = socket.join(Transfer.relayTopic(token)) { ev, _ -> if (ev == "want") scope.launch { flush() } }
        val job = scope.launch {
            while (true) {
                flush()
                delay(800)
            }
        }
        senders[token] = Sender(ch, job)
        onProgress(total, total)
    }

    private class Inbox(var ch: RealtimeSocket.Channel?, val parts: Array<String?> = arrayOfNulls(10_001), var total: Int = 0)

    private val boxes = ConcurrentHashMap<String, Inbox>()

    private fun packed(b: Inbox): Pulled {
        val got = b.parts.take(maxOf(b.total, 0)).count { it != null }
        if (b.total < 1 || got < b.total) return Pulled(got, b.total, null)
        return Pulled(got, b.total, b.parts.take(b.total).joinToString("") { it ?: "" })
    }

    /** Ask the device showing the QR, and keep listening until the vault arrives (about 8 seconds). */
    suspend fun pullTransfer(token: String, onProgress: (Int, Int) -> Unit = { _, _ -> }): Pulled {
        if (!SyncConfig.configured) throw SyncError("qr-nosync")
        val box = boxes.getOrPut(token) { Inbox(null) }
        if (box.ch == null) {
            box.ch = socket.join(Transfer.relayTopic(token)) { ev, p ->
                if (ev == "part") {
                    val seq = p.long("seq")?.toInt() ?: return@join
                    val total = p.long("total")?.toInt() ?: return@join
                    val body = p.str("body") ?: ""
                    if (seq !in 0..10_000 || total !in 1..10_000 || body.length > Transfer.RELAY_FRAME) return@join
                    box.total = total
                    box.parts[seq] = body
                }
            }
        }
        val deadline = System.currentTimeMillis() + 8000
        var lastWant = 0L
        while (System.currentTimeMillis() < deadline) {
            val now = packed(box)
            onProgress(now.got, now.total)
            if (now.body != null) return now
            if (System.currentTimeMillis() - lastWant > 700) {
                lastWant = System.currentTimeMillis()
                box.ch?.send("want", buildJsonObject { put("t", lastWant) })
            }
            delay(200)
        }
        return packed(box)
    }

    fun dropTransfer(token: String) {
        senders.remove(token)?.let { it.job.cancel(); it.ch.close() }
        boxes.remove(token)?.ch?.close()
    }

    /* ---------- roster ---------- */

    interface RosterLink {
        fun publish(body: String)
        fun ask()
        fun close()
    }

    private fun peekRev(body: String): Long = Regex("\"rev\":(\\d+)").find(body)?.groupValues?.get(1)?.toLongOrNull() ?: 0

    private class Gen(val parts: Array<String?>, var total: Int)

    /** Live copy of one vault between devices that already have it. No account; only ciphertext is sent. */
    suspend fun joinRoster(vaultId: String, onFile: (String) -> Unit): RosterLink {
        if (!Regex("^[0-9a-f-]{8,64}$", RegexOption.IGNORE_CASE).matches(vaultId)) throw SyncError("roster-id")
        if (!SyncConfig.configured) throw SyncError("qr-nosync")
        var current = ""
        var gen = ""
        var busy = false
        var closed = false
        val incoming = LinkedHashMap<String, Gen>()
        val maxParts = 8
        lateinit var ch: RealtimeSocket.Channel

        fun flush() {
            if (busy || closed || current.isEmpty()) return
            val parts = Transfer.splitBody(current)
            if (parts.size > maxParts) return
            busy = true
            val mine = gen
            try {
                for (seq in parts.indices) {
                    if (closed || gen != mine) return
                    if (!ch.send("rpart", buildJsonObject { put("gen", mine); put("seq", seq); put("total", parts.size); put("body", parts[seq]) })) return
                }
            } finally {
                busy = false
            }
        }

        fun takePart(p: JsonObject): String? {
            val g = p.str("gen")?.take(80) ?: return null
            val seq = p.long("seq")?.toInt() ?: return null
            val total = p.long("total")?.toInt() ?: return null
            val body = p.str("body") ?: return null
            if (g.isEmpty() || seq !in 0 until maxParts || total !in 1..maxParts || body.length > Transfer.RELAY_FRAME) return null
            synchronized(incoming) {
                var slot = incoming[g]
                if (slot == null) {
                    if (incoming.size > 4) incoming.clear()
                    slot = Gen(arrayOfNulls(maxParts), total)
                    incoming[g] = slot
                }
                slot.total = total
                slot.parts[seq] = body
                if (slot.parts.take(total).any { it == null }) return null
                incoming.remove(g)
                return slot.parts.take(total).joinToString("") { it ?: "" }
            }
        }

        ch = socket.join(Transfer.rosterTopic(vaultId)) { ev, p ->
            when (ev) {
                "rhave" -> {
                    val rev = p.long("rev") ?: return@join
                    val id = p.str("id") ?: ""
                    if (id.isNotEmpty() && id != vaultId) return@join
                    val localRev = if (current.isNotEmpty()) peekRev(current) else -1
                    if (rev > localRev) ch.send("rwant", buildJsonObject { put("rev", localRev) })
                }
                "rwant" -> scope.launch { flush() }
                "rpart" -> takePart(p)?.let(onFile)
            }
        }
        val timer = scope.launch {
            while (true) {
                delay(3000)
                if (!closed && current.isNotEmpty()) ch.send("rhave", buildJsonObject { put("id", vaultId); put("rev", peekRev(current)) })
            }
        }
        ch.send("rwant", buildJsonObject { put("rev", -1) })

        return object : RosterLink {
            override fun publish(body: String) {
                if (closed || body.isEmpty() || body == current || body.length > maxParts * Transfer.RELAY_FRAME) return
                current = body
                gen = "${peekRev(body)}:${body.length}:${System.currentTimeMillis()}"
                ch.send("rhave", buildJsonObject { put("id", vaultId); put("rev", peekRev(body)) })
                scope.launch { flush() }
            }

            override fun ask() {
                if (!closed) ch.send("rwant", buildJsonObject { put("rev", if (current.isNotEmpty()) peekRev(current) else -1) })
            }

            override fun close() {
                closed = true
                timer.cancel()
                ch.close()
            }
        }
    }

    fun shutdown() {
        for (t in senders.keys.toList()) dropTransfer(t)
        socket.shutdown()
    }

    /** Channel for cloud row changes (needs the signed-in token; falls back to polling when the table is not published). */
    class CloudWatch(private val auth: Supabase, private val onChange: () -> Unit) {
        private val socket = RealtimeSocket { auth.accountToken() }
        private var ch: RealtimeSocket.Channel? = null

        suspend fun start(userId: String): Boolean = try {
            ch = socket.join("pevv-blobs:$userId", private = false, changes = true, onChange = onChange)
            true
        } catch (_: SyncError) {
            false
        }

        fun stop() {
            ch?.close()
            socket.shutdown()
        }
    }
}
