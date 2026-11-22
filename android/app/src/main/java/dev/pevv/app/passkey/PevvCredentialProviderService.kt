package dev.pevv.app.passkey

import android.app.PendingIntent
import android.content.Intent
import android.os.CancellationSignal
import android.os.OutcomeReceiver
import androidx.annotation.RequiresApi
import androidx.credentials.exceptions.ClearCredentialException
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.CreateCredentialUnknownException
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.exceptions.GetCredentialUnknownException
import androidx.credentials.provider.AuthenticationAction
import androidx.credentials.provider.BeginCreateCredentialRequest
import androidx.credentials.provider.BeginCreateCredentialResponse
import androidx.credentials.provider.BeginCreatePasswordCredentialRequest
import androidx.credentials.provider.BeginCreatePublicKeyCredentialRequest
import androidx.credentials.provider.BeginGetCredentialRequest
import androidx.credentials.provider.BeginGetCredentialResponse
import androidx.credentials.provider.BeginGetPasswordOption
import androidx.credentials.provider.BeginGetPublicKeyCredentialOption
import androidx.credentials.provider.CreateEntry
import androidx.credentials.provider.CredentialProviderService
import androidx.credentials.provider.PasswordCredentialEntry
import androidx.credentials.provider.ProviderClearCredentialStateRequest
import androidx.credentials.provider.PublicKeyCredentialEntry
import dev.pevv.app.R
import dev.pevv.app.core.PasskeyCore
import dev.pevv.app.core.str
import dev.pevv.app.pevv
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import org.json.JSONObject

/**
 * Credential Manager provider (Android 14+). It answers "which passkeys and passwords can you offer for this request" with names only;
 * nothing secret leaves the vault until [PevvCredentialActivity] has unlocked it and the user confirmed. Passkeys are the same
 * `type: "passkey"` items the desktop provider uses (ES256).
 */
@RequiresApi(34)
class PevvCredentialProviderService : CredentialProviderService() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    private fun activityIntent(action: String, vararg extras: Pair<String, String>): PendingIntent {
        val i = Intent(action).setPackage(packageName).setClass(this, PevvCredentialActivity::class.java)
        extras.forEach { (k, v) -> i.putExtra(k, v) }
        // unique request code per intent; the system fills in the request extras, so the PendingIntent must be mutable
        return PendingIntent.getActivity(this, (action + extras.joinToString { it.second }).hashCode(), i, PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
    }

    override fun onBeginGetCredentialRequest(
        request: BeginGetCredentialRequest, cancellationSignal: CancellationSignal, callback: OutcomeReceiver<BeginGetCredentialResponse, GetCredentialException>,
    ) {
        scope.launch {
            try {
                val ctl = applicationContext.pevv.vault
                val resp = BeginGetCredentialResponse.Builder()
                if (ctl.file == null) { callback.onResult(resp.build()); return@launch }
                if (!ctl.isUnlocked) {
                    // locked: show nothing about the vault, only a way to unlock it
                    resp.addAuthenticationAction(AuthenticationAction(getString(R.string.cp_unlock), activityIntent(ACTION_UNLOCK)))
                    callback.onResult(resp.build())
                    return@launch
                }
                callback.onResult(entriesFor(this@PevvCredentialProviderService, request))
            } catch (e: Exception) {
                callback.onError(GetCredentialUnknownException())
            }
        }
    }

    override fun onBeginCreateCredentialRequest(
        request: BeginCreateCredentialRequest, cancellationSignal: CancellationSignal, callback: OutcomeReceiver<BeginCreateCredentialResponse, CreateCredentialException>,
    ) {
        try {
            val action = when (request) {
                is BeginCreatePublicKeyCredentialRequest -> ACTION_CREATE_PASSKEY
                is BeginCreatePasswordCredentialRequest -> ACTION_CREATE_PASSWORD
                else -> { callback.onError(CreateCredentialUnknownException()); return }
            }
            val entry = CreateEntry.Builder(getString(R.string.app_name), activityIntent(action)).setDescription(getString(R.string.cp_create_desc)).build()
            callback.onResult(BeginCreateCredentialResponse.Builder().addCreateEntry(entry).build())
        } catch (e: Exception) {
            callback.onError(CreateCredentialUnknownException())
        }
    }

    override fun onClearCredentialStateRequest(
        request: ProviderClearCredentialStateRequest, cancellationSignal: CancellationSignal, callback: OutcomeReceiver<Void?, ClearCredentialException>,
    ) {
        callback.onResult(null)
    }

    companion object {
        /** The suggestions for an unlocked vault: names only (passkeys for exactly this rpId, a password for a linked app). */
        fun entriesFor(ctx: android.content.Context, request: BeginGetCredentialRequest): BeginGetCredentialResponse {
            val ctl = ctx.applicationContext.pevv.vault
            val resp = BeginGetCredentialResponse.Builder()
        for (opt in request.beginGetCredentialOptions) {
            when (opt) {
                is BeginGetPublicKeyCredentialOption -> {
                    val rpId = try { JSONObject(opt.requestJson).optString("rpId") } catch (_: Exception) { "" }
                    val allowed = try {
                        val a = JSONObject(opt.requestJson).optJSONArray("allowCredentials")
                        if (a == null || a.length() == 0) null else (0 until a.length()).map { a.getJSONObject(it).optString("id") }.toSet()
                    } catch (_: Exception) { null }
                    if (rpId.isEmpty()) continue
                    for (e in PasskeyCore.forRp(ctl.entries, rpId)) {
                        val cid = e.data.str("credentialId") ?: continue
                        if (allowed != null && cid !in allowed) continue
                        val name = e.data.str("userName") ?: e.title
                        resp.addCredentialEntry(
                            PublicKeyCredentialEntry.Builder(ctx, name, pendingFor(ctx, ACTION_GET_PASSKEY, "entry" to e.id), opt)
                                .setDisplayName(e.data.str("userDisplayName") ?: e.data.str("rpName")).build(),
                        )
                    }
                }
                is BeginGetPasswordOption -> {
                    // password credentials are offered only for apps whose package is linked to a login by the user
                    val pkg = request.callingAppInfo?.packageName ?: continue
                    val linked = ctl.appLinks()[pkg] ?: continue
                    val e = ctl.entries.firstOrNull { it.id == linked && it.type == "login" } ?: continue
                    resp.addCredentialEntry(
                        PasswordCredentialEntry.Builder(ctx, e.username ?: e.title, pendingFor(ctx, ACTION_GET_PASSWORD, "entry" to e.id), opt)
                            .setDisplayName(e.title).build(),
                    )
                }
                else -> {}
            }
        }
            return resp.build()
        }

        private fun pendingFor(ctx: android.content.Context, action: String, vararg extras: Pair<String, String>): PendingIntent {
            val i = Intent(action).setClass(ctx, PevvCredentialActivity::class.java)
            extras.forEach { (k, v) -> i.putExtra(k, v) }
            return PendingIntent.getActivity(ctx, (action + extras.joinToString { it.second }).hashCode(), i, PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        }
        const val ACTION_UNLOCK = "dev.pevv.app.credential.UNLOCK"
        const val ACTION_GET_PASSKEY = "dev.pevv.app.credential.GET_PASSKEY"
        const val ACTION_GET_PASSWORD = "dev.pevv.app.credential.GET_PASSWORD"
        const val ACTION_CREATE_PASSKEY = "dev.pevv.app.credential.CREATE_PASSKEY"
        const val ACTION_CREATE_PASSWORD = "dev.pevv.app.credential.CREATE_PASSWORD"
    }
}
