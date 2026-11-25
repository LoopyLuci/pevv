package dev.pevv.app.security

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricPrompt
import android.os.Build
import android.os.CancellationSignal
import android.os.Handler
import android.os.Looper
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.util.Base64
import dev.pevv.app.core.DeviceMac
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** Copies secrets marked sensitive (hidden from the keyboard clipboard history and previews) and clears them again. */
object Clip {
    private val handler = Handler(Looper.getMainLooper())
    private var clearTask: Runnable? = null
    private var lastClip: String? = null

    fun copySensitive(ctx: Context, label: String, text: String, clearAfterSeconds: Int) {
        val cm = ctx.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val clip = ClipData.newPlainText(label, text)
        clip.description.extras = android.os.PersistableBundle().apply {
            // ClipDescription.EXTRA_IS_SENSITIVE is API 33; the same key is honoured by keyboards on older releases.
            putBoolean(if (Build.VERSION.SDK_INT >= 33) ClipDescription.EXTRA_IS_SENSITIVE else "android.content.extra.IS_SENSITIVE", true)
        }
        cm.setPrimaryClip(clip)
        lastClip = text
        clearTask?.let { handler.removeCallbacks(it) }
        val t = Runnable { clearNow(ctx) }
        clearTask = t
        handler.postDelayed(t, clearAfterSeconds * 1000L)
    }

    /** Clears the clipboard only if it still holds what we put there. */
    fun clearNow(ctx: Context) {
        val cm = ctx.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val mine = lastClip ?: return
        val cur = try { cm.primaryClip?.getItemAt(0)?.text?.toString() } catch (_: Exception) { null }
        if (cur == null || cur == mine) {
            if (Build.VERSION.SDK_INT >= 28) cm.clearPrimaryClip() else cm.setPrimaryClip(ClipData.newPlainText("", ""))
        }
        lastClip = null
        clearTask = null
    }
}

/** Wraps small values under a Keystore key that is not tied to a user presence check (sync tokens). */
object DeviceSeal {
    private const val ALIAS = "pevv_device_seal"

    private fun key(): SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (ks.getKey(ALIAS, null) as? SecretKey)?.let { return it }
        val g = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        g.init(
            KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).setKeySize(256).build(),
        )
        return g.generateKey()
    }

    fun seal(plain: String): String {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, key())
        val ct = c.doFinal(plain.toByteArray(Charsets.UTF_8))
        return Base64.encodeToString(c.iv, Base64.NO_WRAP) + "." + Base64.encodeToString(ct, Base64.NO_WRAP)
    }

    fun open(sealed: String): String? = try {
        val (iv, ct) = sealed.split(".")
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, Base64.decode(iv, Base64.NO_WRAP)))
        String(c.doFinal(Base64.decode(ct, Base64.NO_WRAP)), Charsets.UTF_8)
    } catch (_: Exception) {
        null
    }
}

/**
 * A Keystore HMAC key that never leaves the device. It binds the "authenticator passed on this device" record
 * (see core/Trust.kt), so the record cannot be forged by editing app data. No user presence is needed: it only
 * vouches for a record the app made itself. Returns null when the Keystore is unusable (then nothing is trusted).
 */
object KeystoreDeviceMac : DeviceMac {
    private const val ALIAS = "pevv_trust_hmac"

    private fun key(): SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (ks.getKey(ALIAS, null) as? SecretKey)?.let { return it }
        val g = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, "AndroidKeyStore")
        g.init(KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_SIGN).build())
        return g.generateKey()
    }

    override fun mac(data: ByteArray): ByteArray? = try {
        Mac.getInstance("HmacSHA256").apply { init(key()) }.doFinal(data)
    } catch (_: Exception) {
        null
    }
}

/**
 * Optional biometric quick unlock. A Keystore AES key (StrongBox when the device has one) that needs a fresh strong biometric for
 * every use and is invalidated when a new fingerprint or face is enrolled wraps a copy of the vault key. The master password stays
 * the root of trust: it still opens the vault, and so do the recovery factors, if the Keystore key is gone.
 */
class BiometricVault(private val ctx: Context) {
    private val sp = ctx.getSharedPreferences("pevv_bio", Context.MODE_PRIVATE)

    sealed class Outcome {
        class Ok(val value: ByteArray?) : Outcome()
        class Failed(val reason: String) : Outcome()
        object Cancelled : Outcome()
        /** The key was invalidated by a new biometric enrolment; quick unlock was switched off. */
        object Invalidated : Outcome()
    }

    val available: Boolean
        get() {
            if (Build.VERSION.SDK_INT < 28) return false
            if (Build.VERSION.SDK_INT >= 30) {
                val bm = ctx.getSystemService(BiometricManager::class.java) ?: return false
                return bm.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) == BiometricManager.BIOMETRIC_SUCCESS
            }
            return ctx.packageManager.hasSystemFeature("android.hardware.fingerprint") || ctx.packageManager.hasSystemFeature("android.hardware.biometrics.face")
        }

    val enrolled: Boolean get() = sp.contains("ct") && sp.contains("iv")

    private fun keyStore() = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    private fun createKey(strongBox: Boolean): SecretKey {
        val b = KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).setKeySize(256)
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true)
        if (Build.VERSION.SDK_INT >= 30) b.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
        else @Suppress("DEPRECATION") b.setUserAuthenticationValidityDurationSeconds(-1)
        if (strongBox && Build.VERSION.SDK_INT >= 28) b.setIsStrongBoxBacked(true)
        val g = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        g.init(b.build())
        return g.generateKey()
    }

    private fun newKey(): SecretKey {
        keyStore().deleteEntry(ALIAS)
        return try { createKey(true) } catch (_: Exception) { createKey(false) } // no StrongBox on this device: fall back to the TEE
    }

    /** True when the key sits in a StrongBox secure element. */
    val strongBox: Boolean get() = sp.getBoolean("strongbox", false)

    @androidx.annotation.RequiresApi(28)
    private fun prompt(cipher: Cipher, title: String, subtitle: String, cancel: String, done: (Outcome, Cipher?) -> Unit) {
        val main = ctx.mainExecutor
        val bp = BiometricPrompt.Builder(ctx).setTitle(title).setSubtitle(subtitle)
            .setNegativeButton(cancel, main) { _, _ -> done(Outcome.Cancelled, null) }
            .also { if (Build.VERSION.SDK_INT >= 30) it.setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG) }
            .build()
        bp.authenticate(BiometricPrompt.CryptoObject(cipher), CancellationSignal(), main, object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                done(Outcome.Ok(null), result.cryptoObject?.cipher)
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence?) {
                done(if (errorCode == BiometricPrompt.BIOMETRIC_ERROR_USER_CANCELED || errorCode == BiometricPrompt.BIOMETRIC_ERROR_CANCELED) Outcome.Cancelled else Outcome.Failed(errString?.toString() ?: "error"), null)
            }
        })
    }

    /** Wrap [vaultKey] after a biometric check. The caller wipes its copy. */
    fun enroll(vaultKey: ByteArray, vaultId: String, title: String, subtitle: String, cancel: String, done: (Outcome) -> Unit) {
        if (Build.VERSION.SDK_INT < 28) { done(Outcome.Failed("unsupported")); return }
        try {
            val key = newKey()
            val c = Cipher.getInstance("AES/GCM/NoPadding")
            c.init(Cipher.ENCRYPT_MODE, key)
            val copy = vaultKey.copyOf()
            prompt(c, title, subtitle, cancel) { out, cipher ->
                if (out is Outcome.Ok && cipher != null) {
                    try {
                        val ct = cipher.doFinal(copy)
                        sp.edit().putString("ct", Base64.encodeToString(ct, Base64.NO_WRAP)).putString("iv", Base64.encodeToString(cipher.iv, Base64.NO_WRAP))
                            .putString("vault", vaultId).putBoolean("strongbox", isStrongBox(key)).apply()
                        done(Outcome.Ok(null))
                    } catch (e: Exception) {
                        done(Outcome.Failed(e.message ?: "error"))
                    }
                } else done(out)
                copy.fill(0)
            }
        } catch (e: Exception) {
            done(Outcome.Failed(e.message ?: "error"))
        }
    }

    private fun isStrongBox(key: SecretKey): Boolean = try {
        val info = javax.crypto.SecretKeyFactory.getInstance(key.algorithm, "AndroidKeyStore").getKeySpec(key, android.security.keystore.KeyInfo::class.java) as android.security.keystore.KeyInfo
        if (Build.VERSION.SDK_INT >= 31) info.securityLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX else false
    } catch (_: Exception) {
        false
    }

    /** Ask for the biometric and hand back the unwrapped vault key (the caller wipes it). */
    fun unlock(vaultId: String, title: String, subtitle: String, cancel: String, done: (Outcome) -> Unit) {
        if (Build.VERSION.SDK_INT < 28) { done(Outcome.Failed("unsupported")); return }
        val ct = sp.getString("ct", null)
        val iv = sp.getString("iv", null)
        if (ct == null || iv == null || sp.getString("vault", null) != vaultId) { done(Outcome.Failed("not-enrolled")); return }
        val c: Cipher
        try {
            val key = keyStore().getKey(ALIAS, null) as? SecretKey ?: run { forget(); done(Outcome.Invalidated); return }
            c = Cipher.getInstance("AES/GCM/NoPadding")
            c.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, Base64.decode(iv, Base64.NO_WRAP)))
        } catch (_: KeyPermanentlyInvalidatedException) {
            forget()
            done(Outcome.Invalidated)
            return
        } catch (e: Exception) {
            done(Outcome.Failed(e.message ?: "error"))
            return
        }
        prompt(c, title, subtitle, cancel) { out, cipher ->
            if (out is Outcome.Ok && cipher != null) {
                try { done(Outcome.Ok(cipher.doFinal(Base64.decode(ct, Base64.NO_WRAP)))) } catch (e: Exception) { done(Outcome.Failed(e.message ?: "error")) }
            } else done(out)
        }
    }

    /** Remove the wrapped copy and the Keystore key. */
    fun forget() {
        sp.edit().clear().apply()
        try { keyStore().deleteEntry(ALIAS) } catch (_: Exception) { }
    }

    private companion object {
        const val ALIAS = "pevv_bio_key"
    }
}
