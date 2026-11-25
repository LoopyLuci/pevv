package dev.pevv.app

import dev.pevv.app.core.Bytes
import dev.pevv.app.core.Crypto
import dev.pevv.app.core.DeviceMac
import dev.pevv.app.core.Kdf
import dev.pevv.app.core.Recheck
import dev.pevv.app.core.SecondFactorTrust
import dev.pevv.app.core.TotpConfig
import dev.pevv.app.core.TrustBinding
import dev.pevv.app.core.TrustStorage
import dev.pevv.app.core.VaultEngine
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class TrustTest {
    private val now = 1_900_000_000_000L
    private val day = 24 * 3_600_000L

    private class MemStorage : TrustStorage {
        val m = HashMap<String, Pair<Long, String>>()
        override fun get(vaultId: String) = m[vaultId]
        override fun put(vaultId: String, t: Long, mac: String) { m[vaultId] = t to mac }
        override fun clear(vaultId: String) { m.remove(vaultId) }
    }

    private fun deviceKey(seed: Int) = ByteArray(32) { (it + seed).toByte() }
    private fun mac(seed: Int) = DeviceMac { Crypto.hmacSha256(deviceKey(seed), it) }
    private val vaultKey = ByteArray(32) { (it * 5 + 1).toByte() }
    private fun binding(key: ByteArray = vaultKey, keyEpoch: Long = 0, trustEpoch: Long = 0, device: String = "dev-a") =
        TrustBinding("vault-1", device, key, keyEpoch, trustEpoch)

    @Test fun everyLoginNeverTrusts() {
        assertFalse(SecondFactorTrust.fresh(Recheck.LOGIN, now - 1000, now))
    }

    @Test fun windowsAreExclusiveAtTheEdge() {
        assertTrue(SecondFactorTrust.fresh(Recheck.DAILY, now - day + 1, now))
        assertFalse(SecondFactorTrust.fresh(Recheck.DAILY, now - day, now))
        assertTrue(SecondFactorTrust.fresh(Recheck.WEEKLY, now - 7 * day + 1, now))
        assertFalse(SecondFactorTrust.fresh(Recheck.WEEKLY, now - 7 * day, now))
        assertTrue(SecondFactorTrust.fresh(Recheck.MONTHLY, now - 30 * day + 1, now))
        assertFalse(SecondFactorTrust.fresh(Recheck.MONTHLY, now - 30 * day, now))
    }

    @Test fun newDeviceTrustsAnyPastVerification() {
        assertTrue(SecondFactorTrust.fresh(Recheck.NEW_DEVICE, now - 400 * day, now))
    }

    @Test fun aTimestampInTheFutureIsExpired() {
        for (f in listOf(Recheck.DAILY, Recheck.WEEKLY, Recheck.MONTHLY, Recheck.NEW_DEVICE)) assertFalse(f.id, SecondFactorTrust.fresh(f, now + 1, now))
        assertFalse(SecondFactorTrust.fresh(Recheck.DAILY, 0, now))
        assertFalse(SecondFactorTrust.fresh(Recheck.DAILY, -5, now))
    }

    @Test fun unknownSettingMeansEveryLogin() {
        assertEquals(Recheck.LOGIN, Recheck.parse(null))
        assertEquals(Recheck.LOGIN, Recheck.parse("hourly"))
        assertEquals(Recheck.WEEKLY, Recheck.parse("weekly"))
        assertEquals(Recheck.NEW_DEVICE, Recheck.parse("new-device"))
    }

    @Test fun recordedTrustHoldsInsideTheWindowOnly() {
        val t = SecondFactorTrust(MemStorage(), mac(1))
        t.record(binding(), now)
        assertTrue(t.holds(Recheck.DAILY, binding(), now + day / 2))
        assertFalse(t.holds(Recheck.DAILY, binding(), now + day))
        assertFalse(t.holds(Recheck.LOGIN, binding(), now + 1))
        assertTrue(t.holds(Recheck.NEW_DEVICE, binding(), now + 300 * day))
    }

    @Test fun clockRolledBackExpiresTheRecord() {
        val t = SecondFactorTrust(MemStorage(), mac(1))
        t.record(binding(), now)
        assertFalse(t.holds(Recheck.WEEKLY, binding(), now - 2 * day))
    }

    @Test fun noRecordMeansNewDevice() {
        assertFalse(SecondFactorTrust(MemStorage(), mac(1)).holds(Recheck.NEW_DEVICE, binding(), now))
    }

    @Test fun editingTheStoredFieldDoesNotForgeTrust() {
        val st = MemStorage()
        val t = SecondFactorTrust(st, mac(1))
        t.record(binding(), now)
        val (_, m) = st.get("vault-1")!!
        // Push the timestamp forward to extend the window: the MAC no longer matches.
        st.put("vault-1", now + 5 * day, m)
        assertFalse(t.holds(Recheck.MONTHLY, binding(), now + 6 * day))
        st.put("vault-1", now + 5 * day, Bytes.b64(ByteArray(32)))
        assertFalse(t.holds(Recheck.MONTHLY, binding(), now + 6 * day))
        st.put("vault-1", now, "not base64 !!")
        assertFalse(t.holds(Recheck.MONTHLY, binding(), now + 1))
    }

    @Test fun aRecordFromAnotherDeviceSecretIsRejected() {
        val st = MemStorage()
        SecondFactorTrust(st, mac(1)).record(binding(), now)
        assertFalse(SecondFactorTrust(st, mac(2)).holds(Recheck.MONTHLY, binding(), now + 1))
    }

    @Test fun knowingOnlyTheVaultKeyIsNotEnough() {
        // An attacker with the password derives the vault key but has no device secret: a MAC made without it fails.
        val st = MemStorage()
        val t = SecondFactorTrust(st, mac(1))
        val forged = Crypto.hmacSha256(vaultKey, Bytes.utf8("anything"))
        st.put("vault-1", now, Bytes.b64(forged))
        assertFalse(t.holds(Recheck.MONTHLY, binding(), now + 1))
    }

    @Test fun noDeviceSecretMeansNothingIsTrusted() {
        val st = MemStorage()
        val t = SecondFactorTrust(st, DeviceMac { null })
        t.record(binding(), now)
        assertNull(st.get("vault-1"))
        assertFalse(t.holds(Recheck.MONTHLY, binding(), now + 1))
    }

    @Test fun newKeyOrNewEpochOrOtherDeviceInvalidates() {
        val t = SecondFactorTrust(MemStorage(), mac(1))
        t.record(binding(), now)
        assertTrue(t.holds(Recheck.MONTHLY, binding(), now + 1))
        assertFalse(t.holds(Recheck.MONTHLY, binding(key = ByteArray(32) { 9 }), now + 1))   // key rotation
        assertFalse(t.holds(Recheck.MONTHLY, binding(keyEpoch = 1), now + 1))                 // rotation epoch
        assertFalse(t.holds(Recheck.MONTHLY, binding(trustEpoch = 1), now + 1))               // password change / revoke
        assertFalse(t.holds(Recheck.MONTHLY, binding(device = "dev-b"), now + 1))
    }

    @Test fun forgetClearsTheRecord() {
        val t = SecondFactorTrust(MemStorage(), mac(1))
        t.record(binding(), now)
        t.forget("vault-1")
        assertFalse(t.holds(Recheck.MONTHLY, binding(), now + 1))
    }

    @Test fun replacingTheAuthenticatorBumpsTheEpoch() {
        val kdf = Kdf.Argon2id(19_456, 2, 1, Bytes.b64(ByteArray(16) { 3 }))
        val (file, session) = VaultEngine.createVault("trust test password", kdf, now)
        val meta = VaultEngine.readMeta(file, session)
        assertEquals(0L, SecondFactorTrust.epochOf(meta))
        val (_, m1) = VaultEngine.setTotp(file, session, meta, TotpConfig("JBSWY3DPEHPK3PXP"))
        assertEquals(1L, SecondFactorTrust.epochOf(m1))
        assertEquals(Recheck.LOGIN, SecondFactorTrust.recheckOf(m1))
    }
}
