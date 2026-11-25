package dev.pevv.app.store

import android.content.Context
import android.content.SharedPreferences
import android.os.Build
import dev.pevv.app.core.Devices
import dev.pevv.app.core.TrustStorage
import dev.pevv.app.core.VaultDevice
import java.util.UUID

/**
 * Non-secret, per-installation settings (never the vault key, a password or a decrypted item).
 * The device id is not an account id and never leaves the sealed vault roster.
 */
class AppPrefs(ctx: Context) {
    private val sp: SharedPreferences = ctx.applicationContext.getSharedPreferences("pevv_prefs", Context.MODE_PRIVATE)

    /** Minutes in the background before the vault locks. 0 = lock as soon as the app is left. */
    var lockMinutes: Int
        get() = sp.getInt("lock_minutes", 1)
        set(v) = sp.edit().putInt("lock_minutes", v.coerceIn(0, 60)).apply()

    /** Idle seconds in the foreground before the vault locks. 0 = never while the app is on screen. */
    var idleSeconds: Int
        get() = sp.getInt("idle_seconds", 300)
        set(v) = sp.edit().putInt("idle_seconds", v.coerceIn(0, 3600)).apply()

    var clipboardClearSeconds: Int
        get() = sp.getInt("clip_clear", 30)
        set(v) = sp.edit().putInt("clip_clear", v.coerceIn(5, 300)).apply()

    var syncOn: Boolean
        get() = sp.getBoolean("sync_on", false)
        set(v) = sp.edit().putBoolean("sync_on", v).apply()

    var biometricOn: Boolean
        get() = sp.getBoolean("bio_on", false)
        set(v) = sp.edit().putBoolean("bio_on", v).apply()

    var revealReauthSeconds: Int
        get() = sp.getInt("reveal_reauth", 120)
        set(v) = sp.edit().putInt("reveal_reauth", v).apply()

    var language: String
        get() = sp.getString("lang", "") ?: ""
        set(v) = sp.edit().putString("lang", v).apply()

    var customDeviceName: String
        get() = sp.getString("device_name", "") ?: ""
        set(v) = sp.edit().putString("device_name", Devices.cleanDeviceName(v)).apply()

    /** Random per installation, lowercase hex with dashes (a UUID), the shape the roster accepts. */
    val deviceId: String
        get() {
            val cur = sp.getString("device_id", null)
            if (cur != null && Devices.validDeviceId(cur) && cur.length >= 16) return cur
            val id = UUID.randomUUID().toString()
            sp.edit().putString("device_id", id).apply()
            return id
        }

    /** Vault ids this installation was told to drop; cloud sync must not install them again. */
    fun revokedVaults(): Set<String> = sp.getStringSet("revoked_vaults", emptySet()) ?: emptySet()

    fun markRevoked(id: String) = sp.edit().putStringSet("revoked_vaults", revokedVaults() + id).apply()

    fun clearRevoked(id: String) = sp.edit().putStringSet("revoked_vaults", revokedVaults() - id).apply()

    fun vaultRevokedLocally(id: String) = id in revokedVaults()

    /** When the authenticator was last passed on this device, per vault, with the MAC that binds it (see SecondFactorTrust). */
    val trustStorage: TrustStorage = object : TrustStorage {
        override fun get(vaultId: String): Pair<Long, String>? {
            val v = sp.getString("trust:$vaultId", null)?.split(":", limit = 2) ?: return null
            val t = v.getOrNull(0)?.toLongOrNull() ?: return null
            return t to (v.getOrNull(1) ?: return null)
        }
        override fun put(vaultId: String, t: Long, mac: String) { sp.edit().putString("trust:$vaultId", "$t:$mac").apply() }
        override fun clear(vaultId: String) { sp.edit().remove("trust:$vaultId").apply() }
    }

    /** Attempt limiter state per kind and vault: `fails:until`. */
    fun limiter(key: String): Pair<Int, Long> {
        val v = sp.getString("limit:$key", null)?.split(":") ?: return 0 to 0L
        return (v.getOrNull(0)?.toIntOrNull() ?: 0) to (v.getOrNull(1)?.toLongOrNull() ?: 0L)
    }

    fun setLimiter(key: String, fails: Int, until: Long) = sp.edit().putString("limit:$key", "$fails:$until").apply()

    fun raw(): SharedPreferences = sp

    /** What this installation reports in the sealed roster. The agent string is the app and Android version, never a serial. */
    fun describeDevice(prev: VaultDevice?, tablet: Boolean, now: Long = System.currentTimeMillis()): VaultDevice {
        val kind = if (tablet) "tablet" else "phone"
        val agent = "PEVV app · Android ${Build.VERSION.RELEASE}".take(80)
        val auto = "${if (tablet) "Tablet" else "Phone"} · ${Build.MANUFACTURER} ${Build.MODEL}".take(40)
        return VaultDevice(deviceId, customDeviceName.ifEmpty { prev?.name ?: auto }, kind, prev?.added ?: now, now, agent)
    }
}
