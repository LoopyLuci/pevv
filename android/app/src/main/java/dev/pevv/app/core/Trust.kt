package dev.pevv.app.core

import dev.pevv.app.core.Bytes.b64
import dev.pevv.app.core.Bytes.unb64
import dev.pevv.app.core.Bytes.utf8

/**
 * How often the authenticator (TOTP) is asked for, and the per-device record that makes "not this time" safe
 * (the same design as src/pevv/trust.ts).
 *
 * The setting lives in the sealed vault meta (`secondFactorRecheck`, per vault, synced). The "last verified" record is per
 * device and local. Its `mac` needs BOTH the vault key and a secret that never leaves this device (an Android Keystore key),
 * so editing the stored field, or knowing only the master password, cannot forge it:
 *   tag = HMAC-SHA256(vault key, context | vault id | device id | key epoch | trust epoch | t)
 *   mac = HMAC-SHA256(device key, tag)
 * A new vault key (rotation) or a new trust epoch (password change, revoked device, replaced authenticator) invalidates it.
 * A timestamp in the future (clock set back) counts as expired.
 */
enum class Recheck(val id: String, val windowMs: Long?) {
    LOGIN("login", null),
    DAILY("daily", 24 * HOUR),
    WEEKLY("weekly", 7 * 24 * HOUR),
    MONTHLY("monthly", 30 * 24 * HOUR),
    NEW_DEVICE("new-device", null);

    companion object {
        /** Unknown or missing values mean every login (the strictest). */
        fun parse(s: String?): Recheck = values().firstOrNull { it.id == s } ?: LOGIN
    }
}

private const val HOUR = 3_600_000L

/** A MAC under a secret that never leaves this device. null = no such secret is available (then nothing is trusted). */
fun interface DeviceMac { fun mac(data: ByteArray): ByteArray? }

/** Where the one record per vault is kept. */
interface TrustStorage {
    fun get(vaultId: String): Pair<Long, String>?
    fun put(vaultId: String, t: Long, mac: String)
    fun clear(vaultId: String)
}

class TrustBinding(val vaultId: String, val deviceId: String, val vaultKey: ByteArray, val keyEpoch: Long, val trustEpoch: Long)

class SecondFactorTrust(private val storage: TrustStorage, private val device: DeviceMac) {
    companion object {
        private const val CONTEXT = "luciverse/pevv/v1/2fa-trust"

        /**
         * Is a verification made at `verifiedAt` still good at `now`? A timestamp after `now` (the clock was set back,
         * or the record is bogus) is expired, whatever the setting.
         */
        fun fresh(freq: Recheck, verifiedAt: Long, now: Long): Boolean {
            if (freq == Recheck.LOGIN) return false
            if (verifiedAt <= 0 || verifiedAt > now) return false
            val w = freq.windowMs ?: return true // new device: any past verification
            return now - verifiedAt < w
        }

        fun epochOf(meta: VaultMeta): Long = meta.json.long("trustEpoch")?.takeIf { it >= 0 } ?: 0L
        fun recheckOf(meta: VaultMeta): Recheck = Recheck.parse(meta.json.str("secondFactorRecheck"))
    }

    private fun macFor(b: TrustBinding, t: Long): ByteArray? {
        if (b.vaultKey.isEmpty()) return null
        val input = utf8("$CONTEXT\n${b.vaultId}\n${b.deviceId}\n${b.keyEpoch}\n${b.trustEpoch}\n$t")
        return device.mac(Crypto.hmacSha256(b.vaultKey, input))
    }

    /** Remember that the authenticator was just passed on this device. */
    fun record(b: TrustBinding, now: Long) {
        val mac = try { macFor(b, now) } catch (_: Exception) { null }
        if (mac == null) storage.clear(b.vaultId) else storage.put(b.vaultId, now, b64(mac))
    }

    fun forget(vaultId: String) = storage.clear(vaultId)

    /** May the authenticator be skipped now? Fails closed on any doubt. */
    fun holds(freq: Recheck, b: TrustBinding, now: Long): Boolean {
        if (freq == Recheck.LOGIN) return false
        return try {
            val (t, mac) = storage.get(b.vaultId) ?: return false
            if (!fresh(freq, t, now)) return false
            val want = macFor(b, t) ?: return false
            Bytes.ctEqual(want, unb64(mac))
        } catch (_: Exception) {
            false
        }
    }
}
