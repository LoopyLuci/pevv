package dev.pevv.app.autofill

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import dev.pevv.app.core.Bytes
import dev.pevv.app.core.Crypto
import dev.pevv.app.core.Json
import dev.pevv.app.core.str
import dev.pevv.app.sync.http
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import okhttp3.Request

/**
 * Digital Asset Links: does `https://<host>/.well-known/assetlinks.json` say this Android app may use the site's logins?
 * (relation `delegate_permission/common.get_login_creds`, same package and signing certificate). Results are cached because autofill
 * has a short deadline. Only the host name leaves the phone, and only for a site that is already in the vault.
 */
class AssetLinks(ctx: Context) {
    private val app = ctx.applicationContext
    private val sp = app.getSharedPreferences("pevv_dal", Context.MODE_PRIVATE)

    /** SHA-256 fingerprints of the signing certificates of an installed package, in the `AA:BB:..` form assetlinks.json uses. */
    fun fingerprints(pkg: String): Set<String> = try {
        val sigs = if (Build.VERSION.SDK_INT >= 28) {
            val info = app.packageManager.getPackageInfo(pkg, PackageManager.GET_SIGNING_CERTIFICATES).signingInfo
            if (info == null) emptyList() else if (info.hasMultipleSigners()) info.apkContentsSigners.toList() else info.signingCertificateHistory.toList()
        } else @Suppress("DEPRECATION") app.packageManager.getPackageInfo(pkg, PackageManager.GET_SIGNATURES).signatures?.toList() ?: emptyList()
        sigs.map { s -> Bytes.hex(Crypto.sha256(s.toByteArray())).uppercase().chunked(2).joinToString(":") }.toSet()
    } catch (_: Exception) {
        emptySet()
    }

    fun cached(pkg: String, host: String): Boolean? {
        val v = sp.getString("$pkg|$host", null) ?: return null
        val (ok, at) = v.split(":").let { (it.getOrNull(0) == "1") to (it.getOrNull(1)?.toLongOrNull() ?: 0L) }
        val ttl = if (ok) 7 * 86_400_000L else 86_400_000L
        return if (System.currentTimeMillis() - at < ttl) ok else null
    }

    fun verifiedHosts(pkg: String, hosts: Collection<String>): Set<String> = hosts.filter { cached(pkg, it) == true }.toSet()

    /** Fetch and check (network). Returns the answer and caches it; a network failure is not cached. */
    suspend fun verify(pkg: String, host: String, relation: String = RELATION_LOGIN): Boolean {
        cached(pkg, host)?.let { return it }
        val prints = fingerprints(pkg)
        if (prints.isEmpty()) return false
        val ok = try {
            val body = withContext(Dispatchers.IO) {
                http.newCall(Request.Builder().url("https://$host/.well-known/assetlinks.json").header("Accept", "application/json").build()).execute().use { r ->
                    if (!r.isSuccessful) null else r.body?.string()?.take(512_000)
                }
            } ?: return false.also { remember(pkg, host, false) }
            check(body, pkg, prints, relation)
        } catch (_: Exception) {
            return false
        }
        remember(pkg, host, ok)
        return ok
    }

    private fun remember(pkg: String, host: String, ok: Boolean) {
        sp.edit().putString("$pkg|$host", "${if (ok) 1 else 0}:${System.currentTimeMillis()}").apply()
    }

    companion object {
        const val RELATION_LOGIN = "delegate_permission/common.get_login_creds"

        /** Pure check of an assetlinks.json document. */
        fun check(json: String, pkg: String, prints: Set<String>, relation: String = RELATION_LOGIN): Boolean {
            val arr = try { Json.parse(json) as? JsonArray } catch (_: Exception) { null } ?: return false
            for (st in arr) {
                val o = st as? JsonObject ?: continue
                val rels = (o["relation"] as? JsonArray)?.mapNotNull { (it as? JsonPrimitive)?.content } ?: continue
                if (relation !in rels) continue
                val t = o["target"] as? JsonObject ?: continue
                if (t.str("namespace") != "android_app" || t.str("package_name") != pkg) continue
                val fp = (t["sha256_cert_fingerprints"] as? JsonArray)?.mapNotNull { (it as? JsonPrimitive)?.content?.uppercase() } ?: continue
                if (fp.any { it in prints }) return true
            }
            return false
        }
    }
}
