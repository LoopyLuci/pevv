package dev.pevv.app.sync

import android.content.Context
import android.net.Uri
import dev.pevv.app.BuildConfig
import dev.pevv.app.core.Json
import dev.pevv.app.core.bool
import dev.pevv.app.core.long
import dev.pevv.app.core.obj
import dev.pevv.app.core.str
import dev.pevv.app.core.jstr
import dev.pevv.app.security.DeviceSeal
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.util.concurrent.TimeUnit

/** Build-time sync config: the same two values as VITE_PEVV_SYNC_URL / VITE_PEVV_SYNC_ANON_KEY. Empty = sync and the relay are off. */
object SyncConfig {
    val url: String get() = BuildConfig.SYNC_URL.trim().trimEnd('/')
    val anonKey: String get() = BuildConfig.SYNC_ANON_KEY.trim()
    val publicUrl: String get() = BuildConfig.PUBLIC_URL.trim()
    val rpId: String get() = BuildConfig.RP_ID.trim()
    val configured: Boolean get() = url.startsWith("https://") && anonKey.isNotEmpty()
}

class SyncError(val code: String, msg: String? = null) : Exception(msg ?: code)

/** A GoTrue session. Persisted sealed under a Keystore key; it only ever reaches ciphertext rows. */
class AuthSession(val access: String, val refresh: String, val expiresAt: Long, val userId: String, val email: String?, val anonymous: Boolean) {
    fun toJson(): String = Json.encode(buildJsonObject {
        put("a", access); put("r", refresh); put("e", expiresAt); put("u", userId); email?.let { put("m", it) }; put("n", anonymous)
    })

    companion object {
        fun fromJson(s: String): AuthSession? = try {
            val o = Json.parseObject(s)
            AuthSession(o.str("a")!!, o.str("r")!!, o.long("e") ?: 0, o.str("u")!!, o.str("m"), o.bool("n") ?: false)
        } catch (_: Exception) {
            null
        }

        fun fromResponse(o: JsonObject, now: Long = System.currentTimeMillis() / 1000): AuthSession {
            val access = o.str("access_token") ?: throw SyncError("auth-failed")
            val user = o.obj("user")
            val exp = o.long("expires_at") ?: (now + (o.long("expires_in") ?: 3600))
            return AuthSession(access, o.str("refresh_token") ?: "", exp, user?.str("id") ?: "", user?.str("email"), user?.bool("is_anonymous") ?: false)
        }
    }
}

val http: OkHttpClient by lazy {
    OkHttpClient.Builder().connectTimeout(15, TimeUnit.SECONDS).readTimeout(30, TimeUnit.SECONDS).writeTimeout(30, TimeUnit.SECONDS)
        .pingInterval(25, TimeUnit.SECONDS).build()
}

private val JSON_MT = "application/json".toMediaType()

/**
 * GoTrue and PostgREST over HTTPS (OkHttp, cleartext is off in the network security config). One instance holds the signed-in sync
 * account; the anonymous relay account is a second, separate session (like `storageKey: 'pevv-relay'` on the web).
 */
class Supabase(ctx: Context) {
    private val sp = ctx.applicationContext.getSharedPreferences("pevv_sync", Context.MODE_PRIVATE)
    private val listeners = ArrayList<(AuthSession?) -> Unit>()

    fun onAccount(l: (AuthSession?) -> Unit) { listeners.add(l) }

    private fun load(name: String): AuthSession? = sp.getString(name, null)?.let { DeviceSeal.open(it) }?.let { AuthSession.fromJson(it) }

    private fun store(name: String, s: AuthSession?) {
        if (s == null) sp.edit().remove(name).apply() else sp.edit().putString(name, DeviceSeal.seal(s.toJson())).apply()
    }

    @Volatile private var account: AuthSession? = load("account")
    @Volatile private var relay: AuthSession? = load("relay")

    val currentAccount: AuthSession? get() = account

    private fun setAccount(s: AuthSession?) {
        val changed = s?.userId != account?.userId
        account = s
        store("account", s)
        if (changed) for (l in listeners.toList()) l(s)
    }

    private suspend fun call(method: String, path: String, body: JsonElement? = null, token: String? = null, query: Map<String, String> = emptyMap(), prefer: String? = null): Pair<Int, String> =
        withContext(Dispatchers.IO) {
            if (!SyncConfig.configured) throw SyncError("not-configured")
            val b = (SyncConfig.url + path).toHttpUrl().newBuilder()
            for ((k, v) in query) b.addQueryParameter(k, v)
            val rb = Request.Builder().url(b.build()).header("apikey", SyncConfig.anonKey).header("Authorization", "Bearer ${token ?: SyncConfig.anonKey}")
            prefer?.let { rb.header("Prefer", it) }
            val req = when (method) {
                "GET" -> rb.get().build()
                "DELETE" -> rb.delete().build()
                else -> rb.method(method, Json.encode(body ?: JsonObject(emptyMap())).toRequestBody(JSON_MT)).build()
            }
            try {
                http.newCall(req).execute().use { r -> r.code to (r.body?.string() ?: "") }
            } catch (e: java.io.IOException) {
                throw SyncError("offline", e.message)
            }
        }

    private fun errorOf(code: Int, text: String): SyncError {
        val msg = try { Json.parseObject(text).let { it.str("msg") ?: it.str("error_description") ?: it.str("message") ?: it.str("error") } } catch (_: Exception) { null }
        return SyncError(if (code == 429) "rate-limited" else "http-$code", msg)
    }

    /** Send a one-time code and sign-in link to the address. The link comes back to the app through [handleLink]. */
    suspend fun sendOtp(email: String) {
        val (c, t) = call("POST", "/auth/v1/otp", buildJsonObject { put("email", email.trim()); put("create_user", true) }, query = mapOf("redirect_to" to REDIRECT))
        if (c !in 200..299) throw errorOf(c, t)
    }

    suspend fun verifyOtp(email: String, code: String) {
        val (c, t) = call("POST", "/auth/v1/verify", buildJsonObject { put("type", "email"); put("email", email.trim()); put("token", code.trim()) })
        if (c !in 200..299) throw errorOf(c, t)
        setAccount(AuthSession.fromResponse(Json.parseObject(t)))
    }

    /** `dev.pevv.app://auth#access_token=...&refresh_token=...` (implicit flow) or `?token_hash=...&type=email`. */
    suspend fun handleLink(uri: Uri): Boolean {
        val frag = uri.fragment?.split("&")?.associate { it.substringBefore("=") to Uri.decode(it.substringAfter("=", "")) } ?: emptyMap()
        val access = frag["access_token"]
        if (access != null) {
            val (c, t) = call("GET", "/auth/v1/user", token = access)
            if (c !in 200..299) throw errorOf(c, t)
            val u = Json.parseObject(t)
            setAccount(AuthSession(access, frag["refresh_token"] ?: "", System.currentTimeMillis() / 1000 + (frag["expires_in"]?.toLongOrNull() ?: 3600), u.str("id") ?: "", u.str("email"), u.bool("is_anonymous") ?: false))
            return true
        }
        val hash = uri.getQueryParameter("token_hash") ?: return false
        val (c, t) = call("POST", "/auth/v1/verify", buildJsonObject { put("type", uri.getQueryParameter("type") ?: "email"); put("token_hash", hash) })
        if (c !in 200..299) throw errorOf(c, t)
        setAccount(AuthSession.fromResponse(Json.parseObject(t)))
        return true
    }

    suspend fun signOut() {
        val s = account
        setAccount(null)
        if (s != null) try { call("POST", "/auth/v1/logout", token = s.access) } catch (_: SyncError) { }
    }

    private suspend fun refresh(s: AuthSession): AuthSession? {
        if (s.refresh.isEmpty()) return null
        val (c, t) = call("POST", "/auth/v1/token", buildJsonObject { put("refresh_token", s.refresh) }, query = mapOf("grant_type" to "refresh_token"))
        if (c in 400..499) return null
        if (c !in 200..299) throw errorOf(c, t)
        return AuthSession.fromResponse(Json.parseObject(t))
    }

    /** A valid access token for the sync account, refreshing it when it is about to expire. Null when signed out. */
    suspend fun accountToken(): String? {
        var s = account ?: return null
        if (s.expiresAt - 60 <= System.currentTimeMillis() / 1000) {
            val n = refresh(s)
            if (n == null) { setAccount(null); return null }
            account = n
            store("account", n)
            s = n
        }
        return s.access
    }

    /** The anonymous session used only to open the private relay channels. */
    suspend fun relayToken(): String {
        var s = relay
        if (s != null && s.expiresAt - 60 > System.currentTimeMillis() / 1000) return s.access
        if (s != null) {
            val n = try { refresh(s) } catch (_: SyncError) { null }
            if (n != null) { relay = n; store("relay", n); return n.access }
        }
        val (c, t) = call("POST", "/auth/v1/signup", JsonObject(emptyMap()))
        if (c !in 200..299) throw errorOf(c, t)
        s = AuthSession.fromResponse(Json.parseObject(t))
        relay = s
        store("relay", s)
        return s.access
    }

    /* ---------- pevv_blobs (PostgREST) ---------- */

    class Blob(val path: String, val body: String, val rev: Long = 0)

    /** Answer of the `pevv_put` function (supabase/migrations/0002_pevv_hardening.sql). [conflict] carries the newer server copy. */
    class PutResult(val ok: Boolean, val rev: Long, val error: String? = null, val body: String? = null)

    suspend fun pull(): List<Blob>? {
        val tok = accountToken() ?: return null
        val (c, t) = call("GET", "/rest/v1/pevv_blobs", token = tok, query = mapOf("select" to "path,body,rev", "deleted_at" to "is.null"))
        if (c !in 200..299) return null
        val arr = Json.parse(t) as? JsonArray ?: return null
        return arr.mapNotNull { e ->
            val o = e as? JsonObject ?: return@mapNotNull null
            val p = o.str("path"); val b = o.str("body")
            if (p != null && b != null && p in PATHS && b.length <= MAX_BODY) Blob(p, b, o.long("rev") ?: 0) else null
        }
    }

    /** Compare-and-swap write: the server only accepts it while its row is still at [expectedRev] (0 = no row yet). */
    suspend fun push(path: String, body: String, expectedRev: Long): PutResult {
        require(path in PATHS && body.length <= MAX_BODY) { "cloud-file-rejected" }
        val tok = accountToken() ?: throw SyncError("denied")
        val (c, t) = call("POST", "/rest/v1/rpc/pevv_put", buildJsonObject { put("p_path", path); put("p_body", body); put("p_expected_rev", expectedRev) }, token = tok)
        if (c !in 200..299) throw errorOf(c, t)
        val o = try { Json.parseObject(t) } catch (_: Exception) { throw SyncError("unknown") }
        return PutResult(o.bool("ok") ?: false, o.long("rev") ?: 0, o.str("error"), o.str("body"))
    }

    /** Soft delete: the server keeps the row for a while and `pevv_undelete` brings it back. */
    suspend fun remove(path: String) {
        val tok = accountToken() ?: return
        call("POST", "/rest/v1/rpc/pevv_delete", buildJsonObject { put("p_path", path) }, token = tok)
    }

    companion object {
        /** Where the sign-in link comes back to. Add it to the project's allowed redirect URLs. */
        const val REDIRECT = "dev.pevv.app://auth"
        val PATHS = setOf("/vault/pevv.vault.json", "/vault/pevv-handoff.json")
        const val MAX_BODY = 262_144
        const val SYNC_PATH = "/vault/pevv.vault.json"
        const val MAX_SYNC = 200_000
    }

}
