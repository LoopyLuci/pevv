package dev.pevv.app.autofill

import android.annotation.SuppressLint
import android.app.PendingIntent
import android.app.assist.AssistStructure
import android.content.Context
import android.content.Intent
import android.content.IntentSender
import android.graphics.drawable.Icon
import android.os.Build
import android.os.CancellationSignal
import android.service.autofill.AutofillService
import android.service.autofill.Dataset
import android.service.autofill.FillCallback
import android.service.autofill.FillRequest
import android.service.autofill.FillResponse
import android.service.autofill.InlinePresentation
import android.service.autofill.SaveCallback
import android.service.autofill.SaveInfo
import android.service.autofill.SaveRequest
import android.text.InputType
import android.view.View
import android.view.autofill.AutofillId
import android.view.autofill.AutofillValue
import android.widget.RemoteViews
import android.widget.inline.InlinePresentationSpec
import androidx.autofill.inline.UiVersions
import androidx.autofill.inline.v1.InlineSuggestionUi
import dev.pevv.app.R
import dev.pevv.app.core.Entry
import dev.pevv.app.pevv
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull

/** What the autofill framework told us about one screen. Only structure and hints are kept; typed values are read only on save. */
class ParsedForm(
    val usernameId: AutofillId?, val passwordId: AutofillId?, val pkg: String, val webDomain: String?, val webScheme: String?,
    val typedUser: String?, val typedPassword: String?,
) {
    val fields: List<AutofillId> get() = listOfNotNull(usernameId, passwordId)
    val isLoginForm get() = passwordId != null || usernameId != null
}

object FormParser {
    fun parse(structure: AssistStructure): ParsedForm {
        var user: AssistStructure.ViewNode? = null
        var pass: AssistStructure.ViewNode? = null
        var candidate: AssistStructure.ViewNode? = null
        var web: String? = null
        var scheme: String? = null
        fun walk(n: AssistStructure.ViewNode) {
            if (n.webDomain != null && web == null) {
                web = n.webDomain
                if (Build.VERSION.SDK_INT >= 28) scheme = n.webScheme
            }
            val id = n.autofillId
            if (id != null && n.autofillType == View.AUTOFILL_TYPE_TEXT && n.visibility == View.VISIBLE) {
                when (role(n)) {
                    Role.PASSWORD -> if (pass == null) pass = n
                    Role.USERNAME -> if (user == null && pass == null) user = n
                    Role.TEXT -> if (candidate == null && pass == null) candidate = n
                    Role.OTHER -> {}
                }
            }
            for (i in 0 until n.childCount) walk(n.getChildAt(i))
        }
        var pkg = ""
        for (i in 0 until structure.windowNodeCount) {
            val w = structure.getWindowNodeAt(i)
            if (pkg.isEmpty()) pkg = w.title?.toString()?.substringBefore('/') ?: ""
            walk(w.rootViewNode)
        }
        pkg = structure.activityComponent?.packageName ?: pkg
        // a plain text field right before a password field is the user name
        val u = user ?: if (pass != null) candidate else null
        return ParsedForm(
            u?.autofillId, pass?.autofillId, pkg, web, scheme,
            u?.autofillValue?.takeIf { it.isText }?.textValue?.toString(), pass?.autofillValue?.takeIf { it.isText }?.textValue?.toString(),
        )
    }

    private enum class Role { USERNAME, PASSWORD, TEXT, OTHER }

    private fun role(n: AssistStructure.ViewNode): Role {
        val hints = n.autofillHints?.map { it.lowercase() } ?: emptyList()
        if (hints.any { it == View.AUTOFILL_HINT_PASSWORD || it.contains("password") }) return Role.PASSWORD
        if (hints.any { it == View.AUTOFILL_HINT_USERNAME || it == View.AUTOFILL_HINT_EMAIL_ADDRESS || it.contains("username") || it == "email" }) return Role.USERNAME
        val html = n.htmlInfo
        if (html != null && html.tag.equals("input", true)) {
            val attrs = html.attributes?.associate { it.first.lowercase() to it.second.lowercase() } ?: emptyMap()
            if (attrs["type"] == "password") return Role.PASSWORD
            val ac = attrs["autocomplete"] ?: ""
            if (ac.contains("username") || ac.contains("email")) return Role.USERNAME
            if (attrs["type"] == "email") return Role.USERNAME
            if (attrs["type"] in setOf("text", null, "tel", "")) return Role.TEXT
            return Role.OTHER
        }
        val t = n.inputType
        if ((t and InputType.TYPE_CLASS_TEXT) != 0) {
            val v = t and InputType.TYPE_MASK_VARIATION
            if (v == InputType.TYPE_TEXT_VARIATION_PASSWORD || v == InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD || v == InputType.TYPE_TEXT_VARIATION_WEB_PASSWORD) return Role.PASSWORD
            if (v == InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS || v == InputType.TYPE_TEXT_VARIATION_WEB_EMAIL_ADDRESS) return Role.USERNAME
            return Role.TEXT
        }
        if ((t and InputType.TYPE_CLASS_NUMBER) != 0 && (t and InputType.TYPE_MASK_VARIATION) == InputType.TYPE_NUMBER_VARIATION_PASSWORD) return Role.PASSWORD
        return Role.OTHER
    }
}

/** Builds the datasets and responses. The user name and password values go into a dataset only after the vault is unlocked. */
@SuppressLint("RestrictedApi") // androidx.autofill's own documented way to build an inline suggestion reads `slice`
object FormResponses {
    const val X_ENTRY = "dev.pevv.app.ENTRY"
    const val X_PKG = "dev.pevv.app.PKG"
    const val X_WEB = "dev.pevv.app.WEB"
    const val X_SCHEME = "dev.pevv.app.SCHEME"
    const val X_USER_ID = "dev.pevv.app.USER_ID"
    const val X_PASS_ID = "dev.pevv.app.PASS_ID"

    private fun pi(ctx: Context, code: Int, i: Intent): IntentSender =
        PendingIntent.getActivity(ctx, code, i, PendingIntent.FLAG_CANCEL_CURRENT or PendingIntent.FLAG_MUTABLE).intentSender

    fun authIntent(ctx: Context, form: ParsedForm, entryId: String?, code: Int): IntentSender {
        val i = Intent(ctx, AutofillAuthActivity::class.java).apply {
            putExtra(X_PKG, form.pkg); putExtra(X_WEB, form.webDomain); putExtra(X_SCHEME, form.webScheme)
            putExtra(X_USER_ID, form.usernameId); putExtra(X_PASS_ID, form.passwordId)
            entryId?.let { putExtra(X_ENTRY, it) }
        }
        return pi(ctx, code, i)
    }

    fun pickIntent(ctx: Context, form: ParsedForm): IntentSender {
        val i = Intent(ctx, AutofillAuthActivity::class.java).apply {
            putExtra(X_PKG, form.pkg); putExtra(X_WEB, form.webDomain); putExtra(X_SCHEME, form.webScheme)
            putExtra(X_USER_ID, form.usernameId); putExtra(X_PASS_ID, form.passwordId); putExtra("pick", true)
        }
        return pi(ctx, 7777, i)
    }

    private fun row(ctx: Context, title: String, sub: String): RemoteViews =
        RemoteViews(ctx.packageName, R.layout.autofill_item).apply { setTextViewText(R.id.af_title, title); setTextViewText(R.id.af_sub, sub) }

    private fun inline(ctx: Context, specs: List<InlinePresentationSpec>?, index: Int, title: String, sub: String, attribution: IntentSender?): InlinePresentation? {
        if (Build.VERSION.SDK_INT < 30 || specs.isNullOrEmpty()) return null
        val spec = specs[minOf(index, specs.size - 1)]
        if (!UiVersions.getVersions(spec.style).contains(UiVersions.INLINE_UI_VERSION_1)) return null
        val attr = PendingIntent.getService(ctx, 0, Intent(ctx, PevvAutofillService::class.java), PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        val content = InlineSuggestionUi.newContentBuilder(attr).setTitle(title).setSubtitle(sub)
            .setStartIcon(Icon.createWithResource(ctx, R.drawable.pevv_logo)).build()
        @Suppress("UNUSED_EXPRESSION") attribution
        return InlinePresentation(content.slice, spec, false)
    }

    /** One dataset that asks for authentication before it fills anything (placeholder values only). */
    fun lockedDataset(ctx: Context, form: ParsedForm, e: Entry, specs: List<InlinePresentationSpec>?, index: Int): Dataset {
        val title = e.title.ifEmpty { e.site ?: "PEVV" }
        val sub = e.username ?: ""
        val b = Dataset.Builder(row(ctx, title, sub))
        val inl = inline(ctx, specs, index, title, sub, null)
        for (id in form.fields) {
            if (inl != null && Build.VERSION.SDK_INT >= 30) b.setValue(id, null, row(ctx, title, sub), inl) else b.setValue(id, null, row(ctx, title, sub))
        }
        b.setAuthentication(authIntent(ctx, form, e.id, 100 + index))
        return b.build()
    }

    /** The real dataset, built inside the authentication activity after the unlock. */
    fun filledDataset(ctx: Context, form: ParsedForm, e: Entry): Dataset {
        val title = e.title.ifEmpty { e.site ?: "PEVV" }
        val b = Dataset.Builder(row(ctx, title, e.username ?: ""))
        form.usernameId?.let { b.setValue(it, AutofillValue.forText(e.username ?: "")) }
        form.passwordId?.let { b.setValue(it, AutofillValue.forText(e.password ?: "")) }
        return b.build()
    }

    fun saveInfo(form: ParsedForm): SaveInfo? {
        val pass = form.passwordId ?: return null
        val b = SaveInfo.Builder(SaveInfo.SAVE_DATA_TYPE_PASSWORD, arrayOf(pass))
        form.usernameId?.let { b.setOptionalIds(arrayOf(it)) }
        b.setFlags(SaveInfo.FLAG_SAVE_ON_ALL_VIEWS_INVISIBLE)
        return b.build()
    }
}

/** Short-lived, in-memory only: a login the user may save, waiting for the vault to be unlocked. Never written to disk. */
object PendingSave {
    class Item(val site: String, val pkg: String, val username: String, val password: String, val at: Long = System.currentTimeMillis())

    @Volatile var item: Item? = null

    fun take(): Item? {
        val i = item
        item = null
        return i?.takeIf { System.currentTimeMillis() - it.at < 5 * 60_000 }
    }
}

/**
 * The autofill service. Locked: one "Unlock PEVV" suggestion and no vault data. Unlocked: one suggestion per matching login
 * (title and user name only); the password goes into the form only after [AutofillAuthActivity] has confirmed the vault is unlocked.
 */
@SuppressLint("RestrictedApi")
class PevvAutofillService : AutofillService() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    override fun onFillRequest(request: FillRequest, cancellationSignal: CancellationSignal, callback: FillCallback) {
        val structure = request.fillContexts.last().structure
        val form = FormParser.parse(structure)
        if (!form.isLoginForm || form.pkg == packageName) { callback.onSuccess(null); return }
        val job = scope.launch {
            val app = applicationContext.pevv
            val ctl = app.vault
            val specs = if (Build.VERSION.SDK_INT >= 30) request.inlineSuggestionsRequest?.inlinePresentationSpecs else null
            val resp = FillResponse.Builder()
            FormResponses.saveInfo(form)?.let { resp.setSaveInfo(it) }
            if (ctl.file == null) { callback.onSuccess(null); return@launch }
            if (!ctl.isUnlocked) {
                // Nothing about the vault is revealed while locked, not even whether anything matches.
                val rv = RemoteViews(packageName, R.layout.autofill_item).apply {
                    setTextViewText(R.id.af_title, getString(R.string.af_unlock)); setTextViewText(R.id.af_sub, getString(R.string.af_unlock_sub))
                }
                val inl = if (Build.VERSION.SDK_INT >= 30) specs?.firstOrNull()?.let { s ->
                    if (UiVersions.getVersions(s.style).contains(UiVersions.INLINE_UI_VERSION_1)) {
                        val attr = PendingIntent.getService(this@PevvAutofillService, 0, Intent(this@PevvAutofillService, PevvAutofillService::class.java), PendingIntent.FLAG_IMMUTABLE)
                        InlinePresentation(InlineSuggestionUi.newContentBuilder(attr).setTitle(getString(R.string.af_unlock)).build().slice, s, false)
                    } else null
                } else null
                val sender = FormResponses.authIntent(this@PevvAutofillService, form, null, 1)
                if (inl != null && Build.VERSION.SDK_INT >= 30) resp.setAuthentication(form.fields.toTypedArray(), sender, rv, inl) else resp.setAuthentication(form.fields.toTypedArray(), sender, rv)
                callback.onSuccess(resp.build())
                return@launch
            }
            val matches = AutofillMatcher.find(this@PevvAutofillService, form)
            if (matches.isEmpty()) {
                // For a native app with no match, offer to choose a login (and link it to the app); never for a web page.
                if (form.webDomain == null) {
                    val rv = RemoteViews(packageName, R.layout.autofill_item).apply {
                        setTextViewText(R.id.af_title, getString(R.string.af_choose)); setTextViewText(R.id.af_sub, getString(R.string.af_choose_sub))
                    }
                    val b = Dataset.Builder(rv)
                    for (id in form.fields) b.setValue(id, null, rv)
                    b.setAuthentication(FormResponses.pickIntent(this@PevvAutofillService, form))
                    resp.addDataset(b.build())
                    callback.onSuccess(resp.build())
                } else callback.onSuccess(if (form.passwordId != null) resp.build() else null)
                return@launch
            }
            matches.take(5).forEachIndexed { i, e -> resp.addDataset(FormResponses.lockedDataset(this@PevvAutofillService, form, e, specs, i)) }
            callback.onSuccess(resp.build())
        }
        cancellationSignal.setOnCancelListener { job.cancel() }
    }

    override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
        val form = FormParser.parse(request.fillContexts.last().structure)
        val pass = form.typedPassword
        if (pass.isNullOrEmpty() || form.pkg == packageName) { callback.onSuccess(); return }
        val site = if (form.webDomain != null) "${form.webScheme ?: "https"}://${form.webDomain}" else ""
        PendingSave.item = PendingSave.Item(site, form.pkg, form.typedUser ?: "", pass)
        val i = Intent(this, AutofillSaveActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        if (Build.VERSION.SDK_INT >= 28) {
            callback.onSuccess(PendingIntent.getActivity(this, 5, i, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_CANCEL_CURRENT).intentSender)
        } else {
            // Before Android 9 the service cannot open a screen from here; only save when the vault is already unlocked.
            if (applicationContext.pevv.vault.isUnlocked) startActivity(i) else PendingSave.item = null
            callback.onSuccess()
        }
    }
}

object AutofillMatcher {
    /** Logins that may fill this form. Web pages: exact origin. Native apps: linked by the user, or proven by Digital Asset Links. */
    suspend fun find(ctx: Context, form: ParsedForm): List<Entry> {
        val app = ctx.applicationContext.pevv
        val entries = app.vault.entries
        if (form.webDomain != null) return Matching.forWeb(entries, form.webDomain, form.webScheme)
        val dal = AssetLinks(ctx)
        val logins = Matching.logins(entries)
        val domain = Matching.candidateDomain(form.pkg)
        val hosts = logins.mapNotNull { Matching.parseOrigin(it.site)?.host }.distinct().filter { h -> domain != null && Matching.hostBelongsTo(h, domain) }
        // verify at most a few candidate hosts, within the autofill deadline; results are cached
        withTimeoutOrNull(2500) { for (h in hosts.take(4)) dal.verify(form.pkg, h) }
        return Matching.forApp(entries, form.pkg, app.vault.appLinks(), dal.verifiedHosts(form.pkg, hosts))
    }
}
