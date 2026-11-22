package dev.pevv.app.passkey

import android.app.Activity
import android.content.Intent
import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricPrompt
import android.os.Bundle
import android.os.CancellationSignal
import androidx.activity.compose.setContent
import androidx.annotation.RequiresApi
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.credentials.CreatePasswordRequest
import androidx.credentials.CreatePasswordResponse
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.GetCredentialResponse
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PasswordCredential
import androidx.credentials.PublicKeyCredential
import androidx.credentials.exceptions.CreateCredentialCancellationException
import androidx.credentials.exceptions.GetCredentialCancellationException
import androidx.credentials.provider.CallingAppInfo
import androidx.credentials.provider.PendingIntentHandler
import dev.pevv.app.R
import dev.pevv.app.autofill.AssetLinks
import dev.pevv.app.autofill.SecureActivity
import dev.pevv.app.autofill.UnlockGate
import dev.pevv.app.core.Bytes
import dev.pevv.app.core.Crypto
import dev.pevv.app.core.EntryKinds
import dev.pevv.app.core.PasskeyCore
import dev.pevv.app.core.jnum
import dev.pevv.app.core.jstr
import dev.pevv.app.core.str
import dev.pevv.app.core.with
import dev.pevv.app.pevv
import dev.pevv.app.ui.PevvTheme
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonElement
import org.json.JSONObject

/**
 * The screen Credential Manager opens when the user picks a PEVV passkey or password, or asks to save a new one. It unlocks the vault,
 * checks who is asking, asks for user verification (screen lock or biometrics) and only then signs or stores. FLAG_SECURE comes from [SecureActivity].
 */
@RequiresApi(34)
class PevvCredentialActivity : SecureActivity() {
    private var error by mutableStateOf<String?>(null)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val action = intent.action ?: ""
        setContent {
            PevvTheme {
                UnlockGate {
                    when (action) {
                        PevvCredentialProviderService.ACTION_UNLOCK -> Done { resultForUnlock() }
                        else -> Confirm(action)
                    }
                }
            }
        }
    }

    @Composable
    private fun Done(run: () -> Unit) {
        androidx.compose.runtime.LaunchedEffect(Unit) { run() }
    }

    /** After unlocking from the "Unlock PEVV" action Credential Manager asks again, now with entries. */
    private fun resultForUnlock() {
        val r = Intent()
        val begin = PendingIntentHandler.retrieveBeginGetCredentialRequest(intent)
        PendingIntentHandler.setBeginGetCredentialResponse(r, if (begin == null) androidx.credentials.provider.BeginGetCredentialResponse() else PevvCredentialProviderService.entriesFor(this, begin))
        setResult(Activity.RESULT_OK, r)
        finish()
    }

    @Composable
    private fun Confirm(action: String) {
        var busy by remember { mutableStateOf(false) }
        val creating = action == PevvCredentialProviderService.ACTION_CREATE_PASSKEY || action == PevvCredentialProviderService.ACTION_CREATE_PASSWORD
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text(stringResource(if (creating) R.string.cp_create_title else R.string.cp_get_title), style = MaterialTheme.typography.titleLarge)
            Text(stringResource(R.string.cp_confirm_body), style = MaterialTheme.typography.bodyMedium)
            error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
            Button(enabled = !busy, modifier = Modifier.fillMaxWidth(), onClick = {
                busy = true
                error = null
                verifyUser { uv ->
                    try {
                        when (action) {
                            PevvCredentialProviderService.ACTION_GET_PASSKEY -> doGetPasskey(uv)
                            PevvCredentialProviderService.ACTION_GET_PASSWORD -> doGetPassword()
                            PevvCredentialProviderService.ACTION_CREATE_PASSKEY -> doCreatePasskey(uv)
                            PevvCredentialProviderService.ACTION_CREATE_PASSWORD -> doCreatePassword()
                            else -> fail(action)
                        }
                    } catch (e: Refused) {
                        busy = false
                        error = getString(e.res)
                    } catch (e: Exception) {
                        busy = false
                        error = getString(R.string.err_generic)
                    }
                }
            }) { Text(stringResource(R.string.cp_continue)) }
            OutlinedButton(onClick = { fail(action) }, Modifier.fillMaxWidth()) { Text(stringResource(R.string.cancel)) }
        }
    }

    private class Refused(val res: Int) : Exception()

    private fun fail(action: String) {
        val r = Intent()
        if (action.contains("CREATE")) PendingIntentHandler.setCreateCredentialException(r, CreateCredentialCancellationException())
        else PendingIntentHandler.setGetCredentialException(r, GetCredentialCancellationException())
        setResult(Activity.RESULT_OK, r)
        finish()
    }

    /** User verification: screen lock or biometrics. If the device has none, the vault unlock just done is the only check (UV flag off). */
    private fun verifyUser(done: (Boolean) -> Unit) {
        val bm = getSystemService(BiometricManager::class.java)
        val auth = BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL
        if (bm.canAuthenticate(auth) != BiometricManager.BIOMETRIC_SUCCESS) { done(false); return }
        val p = BiometricPrompt.Builder(this).setTitle(getString(R.string.cp_get_title)).setAllowedAuthenticators(auth).build()
        p.authenticate(CancellationSignal(), mainExecutor, object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) = done(true)
            override fun onAuthenticationError(errorCode: Int, errString: CharSequence?) { error = errString?.toString() }
        })
    }

    /* ---------- who is asking ---------- */

    private class Caller(val origin: String, val clientDataHashGiven: ByteArray?, val pkg: String)

    private fun b64urlOfCert(app: CallingAppInfo): String {
        val prints = AssetLinks(this).fingerprints(app.packageName)
        val fp = prints.firstOrNull() ?: throw Refused(R.string.cp_err_caller)
        return Bytes.b64url(Bytes.unhex(fp.replace(":", "").lowercase()))
    }

    /**
     * The origin the relying party will see. An ordinary app gets `android:apk-key-hash:<cert>` and must be linked to the rpId by Digital
     * Asset Links. A browser (privileged caller) supplies the page origin and the client data hash; that is trusted only when the
     * browser is in the allow-list shipped in assets, otherwise the request is refused.
     */
    private fun resolveCaller(app: CallingAppInfo, rpId: String, givenHash: ByteArray?): Caller {
        if (givenHash != null || app.isOriginPopulated()) {
            val list = try { assets.open("privileged_browsers.json").bufferedReader().use { it.readText() } } catch (_: Exception) { null }
            val origin = list?.let { try { app.getOrigin(it) } catch (_: Exception) { null } }
            if (origin == null || givenHash == null) throw Refused(R.string.cp_err_browser)
            val host = try { java.net.URI(origin).host } catch (_: Exception) { null }
            if (host == null || !(host == rpId || host.endsWith(".$rpId"))) throw Refused(R.string.cp_err_origin)
            return Caller(origin, givenHash, app.packageName)
        }
        val ok = runBlocking { AssetLinks(this@PevvCredentialActivity).verify(app.packageName, rpId) }
        if (!ok) throw Refused(R.string.cp_err_dal)
        return Caller("android:apk-key-hash:" + b64urlOfCert(app), null, app.packageName)
    }

    private fun clientData(type: String, challenge: String, c: Caller): Pair<String, ByteArray> {
        val j = JSONObject().put("type", type).put("challenge", challenge).put("origin", c.origin)
        if (c.origin.startsWith("android:")) j.put("androidPackageName", c.pkg)
        val text = j.toString().replace("\\/", "/")
        return Bytes.b64url(text.toByteArray()) to Crypto.sha256(text.toByteArray())
    }

    /* ---------- get ---------- */

    private fun doGetPasskey(uv: Boolean) {
        val req = PendingIntentHandler.retrieveProviderGetCredentialRequest(intent) ?: throw Refused(R.string.err_generic)
        val opt = req.credentialOptions.filterIsInstance<GetPublicKeyCredentialOption>().firstOrNull() ?: throw Refused(R.string.err_generic)
        val ctl = pevv.vault
        val e = ctl.entries.firstOrNull { it.id == intent.getStringExtra("entry") && it.isPasskey } ?: throw Refused(R.string.err_generic)
        val j = JSONObject(opt.requestJson)
        val rpId = j.optString("rpId")
        if (rpId.isEmpty() || e.data.str("rpId") != rpId) throw Refused(R.string.cp_err_origin)
        val caller = resolveCaller(req.callingAppInfo, rpId, opt.clientDataHash)
        val (cdJson, hash) = if (caller.clientDataHashGiven != null) "" to caller.clientDataHashGiven else clientData("webauthn.get", j.getString("challenge"), caller)
        val a = PasskeyCore.signAssertion(e.data, hash, uv)
        runBlocking { ctl.saveEntry(e.id, e.data.with(mapOf("signCount" to jnum(a.signCount)))) }
        val resp = JSONObject()
            .put("id", a.credentialId).put("rawId", a.credentialId).put("type", "public-key").put("authenticatorAttachment", "platform")
            .put("clientExtensionResults", JSONObject())
            .put(
                "response",
                JSONObject().put("authenticatorData", Bytes.b64url(a.authData)).put("signature", Bytes.b64url(a.signature))
                    .put("userHandle", a.userHandle).apply { if (cdJson.isNotEmpty()) put("clientDataJSON", cdJson) else put("clientDataJSON", "") },
            )
        val r = Intent()
        PendingIntentHandler.setGetCredentialResponse(r, GetCredentialResponse(PublicKeyCredential(resp.toString())))
        setResult(Activity.RESULT_OK, r)
        finish()
    }

    private fun doGetPassword() {
        val ctl = pevv.vault
        val e = ctl.entries.firstOrNull { it.id == intent.getStringExtra("entry") && it.type == "login" } ?: throw Refused(R.string.err_generic)
        val r = Intent()
        PendingIntentHandler.setGetCredentialResponse(r, GetCredentialResponse(PasswordCredential(e.username ?: "", e.password ?: "")))
        setResult(Activity.RESULT_OK, r)
        finish()
    }

    /* ---------- create ---------- */

    private fun doCreatePasskey(uv: Boolean) {
        val req = PendingIntentHandler.retrieveProviderCreateCredentialRequest(intent) ?: throw Refused(R.string.err_generic)
        val cr = req.callingRequest as? CreatePublicKeyCredentialRequest ?: throw Refused(R.string.err_generic)
        val j = JSONObject(cr.requestJson)
        val rp = j.getJSONObject("rp")
        val user = j.getJSONObject("user")
        val rpId = rp.optString("id")
        if (!PasskeyCore.validRpId(rpId)) throw Refused(R.string.cp_err_origin)
        // ES256 must be one of the algorithms the site accepts
        val algs = j.optJSONArray("pubKeyCredParams")
        if (algs != null && (0 until algs.length()).none { algs.getJSONObject(it).optInt("alg") == PasskeyCore.COSE_ES256 }) throw Refused(R.string.cp_err_alg)
        val caller = resolveCaller(req.callingAppInfo, rpId, cr.clientDataHash)
        val (cdJson, _) = if (caller.clientDataHashGiven != null) "" to caller.clientDataHashGiven else clientData("webauthn.create", j.getString("challenge"), caller)
        val ctl = pevv.vault
        val made = PasskeyCore.createPasskey(
            rpId, rp.optString("name").ifEmpty { null }, user.getString("id"), user.optString("name"), user.optString("displayName").ifEmpty { null }, uv,
        )
        runBlocking { ctl.saveEntry(null, made.data) }
        val raw = Bytes.unb64url(made.data.str("passkeyPublicKey") ?: "")
        val spki = byteArrayOf(
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86.toByte(), 0x48, 0xce.toByte(), 0x3d, 0x02, 0x01,
            0x06, 0x08, 0x2a, 0x86.toByte(), 0x48, 0xce.toByte(), 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
        ) + raw
        val resp = JSONObject()
            .put("id", made.credentialId).put("rawId", made.credentialId).put("type", "public-key").put("authenticatorAttachment", "platform")
            .put("clientExtensionResults", JSONObject())
            .put(
                "response",
                JSONObject().put("clientDataJSON", cdJson).put("attestationObject", Bytes.b64url(PasskeyCore.attestationObjectNone(made.authData)))
                    .put("transports", org.json.JSONArray().put("internal")).put("publicKeyAlgorithm", PasskeyCore.COSE_ES256)
                    .put("publicKey", Bytes.b64url(spki)).put("authenticatorData", Bytes.b64url(made.authData)),
            )
        val r = Intent()
        PendingIntentHandler.setCreateCredentialResponse(r, CreatePublicKeyCredentialResponse(resp.toString()))
        setResult(Activity.RESULT_OK, r)
        finish()
    }

    private fun doCreatePassword() {
        val req = PendingIntentHandler.retrieveProviderCreateCredentialRequest(intent) ?: throw Refused(R.string.err_generic)
        val cr = req.callingRequest as? CreatePasswordRequest ?: throw Refused(R.string.err_generic)
        val pkg = req.callingAppInfo.packageName
        val ctl = pevv.vault
        val m = LinkedHashMap<String, JsonElement?>()
        m["title"] = jstr(pkg)
        m["username"] = jstr(cr.id)
        m["password"] = jstr(cr.password)
        val e = runBlocking { ctl.saveEntry(null, EntryKinds.applyEdit(EntryKinds.newData("login"), m)) }
        runBlocking { ctl.linkApp(pkg, e.id) }
        val r = Intent()
        PendingIntentHandler.setCreateCredentialResponse(r, CreatePasswordResponse())
        setResult(Activity.RESULT_OK, r)
        finish()
    }
}
