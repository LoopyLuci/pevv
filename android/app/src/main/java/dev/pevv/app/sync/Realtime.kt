package dev.pevv.app.sync

import dev.pevv.app.core.Json
import dev.pevv.app.core.str
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

/**
 * A small Phoenix-channels client for Supabase Realtime (wire protocol 1.0.0): broadcast channels (the relay and the roster) and
 * `postgres_changes` (live cloud updates). One socket per token source; it reconnects and re-joins by itself.
 */
class RealtimeSocket(private val tokenProvider: suspend () -> String?) {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val ref = AtomicInteger(1)
    private val channels = ConcurrentHashMap<String, Channel>()
    private val pendingReplies = ConcurrentHashMap<String, CompletableDeferred<JsonObject>>()
    @Volatile private var ws: WebSocket? = null
    @Volatile private var open = CompletableDeferred<Unit>()
    @Volatile private var closed = false
    private var heartbeat: Job? = null
    private var connecting = false

    inner class Channel(val topic: String, private val private: Boolean, private val changes: Boolean, val onBroadcast: (String, JsonObject) -> Unit, val onChange: () -> Unit) {
        val joinRef = ref.getAndIncrement().toString()
        @Volatile var joined = false

        fun send(event: String, payload: JsonObject): Boolean {
            val w = ws ?: return false
            if (!joined) return false
            val msg = buildJsonObject {
                put("topic", "realtime:$topic"); put("event", "broadcast"); put("ref", ref.getAndIncrement().toString()); put("join_ref", joinRef)
                put("payload", buildJsonObject { put("type", "broadcast"); put("event", event); put("payload", payload) })
            }
            return w.send(Json.encode(msg))
        }

        suspend fun join(token: String): Boolean {
            val w = ws ?: return false
            val r = ref.getAndIncrement().toString()
            val reply = CompletableDeferred<JsonObject>()
            pendingReplies[r] = reply
            val cfg = buildJsonObject {
                put("broadcast", buildJsonObject { put("ack", false); put("self", false) })
                put("presence", buildJsonObject { put("key", ""); put("enabled", false) })
                put("postgres_changes", kotlinx.serialization.json.JsonArray(if (changes) listOf(buildJsonObject { put("event", "*"); put("schema", "public"); put("table", "pevv_blobs") }) else emptyList()))
                put("private", private)
            }
            val msg = buildJsonObject {
                put("topic", "realtime:$topic"); put("event", "phx_join"); put("ref", r); put("join_ref", joinRef)
                put("payload", buildJsonObject { put("config", cfg); put("access_token", token) })
            }
            if (!w.send(Json.encode(msg))) return false
            val res = withTimeoutOrNull(8000) { reply.await() }
            pendingReplies.remove(r)
            joined = res?.str("status") == "ok"
            return joined
        }

        fun close() {
            channels.remove(topic)
            if (joined) ws?.send(Json.encode(buildJsonObject {
                put("topic", "realtime:$topic"); put("event", "phx_leave"); put("ref", ref.getAndIncrement().toString()); put("payload", JsonObject(emptyMap()))
            }))
            joined = false
        }
    }

    private fun url(): String = SyncConfig.url.replaceFirst("https://", "wss://") + "/realtime/v1/websocket?apikey=${SyncConfig.anonKey}&vsn=1.0.0"

    private suspend fun connect(): Boolean {
        if (closed) return false
        if (open.isCompleted && ws != null) return true
        synchronized(this) {
            if (!connecting) {
                connecting = true
                open = CompletableDeferred()
                ws = http.newWebSocket(Request.Builder().url(url()).build(), listener)
            }
        }
        return withTimeoutOrNull(8000) { open.await(); true } ?: false
    }

    private val listener = object : WebSocketListener() {
        override fun onOpen(webSocket: WebSocket, response: Response) {
            connecting = false
            open.complete(Unit)
            heartbeat?.cancel()
            heartbeat = scope.launch {
                while (true) {
                    delay(25_000)
                    ws?.send(Json.encode(buildJsonObject { put("topic", "phoenix"); put("event", "heartbeat"); put("payload", JsonObject(emptyMap())); put("ref", ref.getAndIncrement().toString()) }))
                }
            }
        }

        override fun onMessage(webSocket: WebSocket, text: String) {
            val o = try { Json.parseObject(text) } catch (_: Exception) { return }
            val topic = (o.str("topic") ?: "").removePrefix("realtime:")
            when (o.str("event")) {
                "phx_reply" -> o.str("ref")?.let { r -> pendingReplies.remove(r)?.complete((o["payload"] as? JsonObject) ?: JsonObject(emptyMap())) }
                "broadcast" -> {
                    val p = o["payload"] as? JsonObject ?: return
                    val ev = p.str("event") ?: return
                    channels[topic]?.onBroadcast?.invoke(ev, (p["payload"] as? JsonObject) ?: JsonObject(emptyMap()))
                }
                "postgres_changes" -> channels[topic]?.onChange?.invoke()
                "phx_close", "phx_error" -> channels[topic]?.joined = false
            }
        }

        override fun onClosed(webSocket: WebSocket, code: Int, reason: String) = dropped()
        override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) = dropped()
    }

    private fun dropped() {
        connecting = false
        heartbeat?.cancel()
        ws = null
        if (open.isCompleted) open = CompletableDeferred()
        for (c in channels.values) c.joined = false
        if (closed || channels.isEmpty()) return
        // Reconnect and re-join what was open.
        scope.launch {
            var wait = 2000L
            while (!closed && channels.isNotEmpty() && ws == null) {
                delay(wait)
                wait = minOf(wait * 2, 30_000)
                try {
                    val tok = tokenProvider() ?: continue
                    if (connect()) for (c in channels.values.toList()) c.join(tok)
                } catch (_: Exception) {
                }
            }
        }
    }

    /** Join a topic; throws `qr-nosync` when the socket or the join does not succeed in time. */
    suspend fun join(topic: String, private: Boolean = true, changes: Boolean = false, onChange: () -> Unit = {}, onBroadcast: (String, JsonObject) -> Unit = { _, _ -> }): Channel {
        val tok = tokenProvider() ?: throw SyncError("qr-nosync")
        if (!connect()) throw SyncError("qr-nosync")
        val ch = Channel(topic, private, changes, onBroadcast, onChange)
        channels[topic] = ch
        if (!ch.join(tok)) {
            channels.remove(topic)
            throw SyncError("qr-nosync")
        }
        return ch
    }

    fun shutdown() {
        closed = true
        heartbeat?.cancel()
        ws?.close(1000, null)
        ws = null
    }

}
