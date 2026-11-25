package dev.pevv.app

import android.content.Context
import android.content.Intent
import android.content.res.Configuration
import android.os.Bundle
import android.view.MotionEvent
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import dev.pevv.app.ui.AppRoot
import dev.pevv.app.ui.PevvTheme
import dev.pevv.app.update.UpdateManager
import kotlinx.coroutines.launch
import java.util.Locale

/** Wraps a context so it uses the language chosen in Settings (English or Spanish), or the system one. */
fun Context.withAppLocale(): Context {
    val lang = try { pevv.prefs.language } catch (_: Exception) { "" }
    if (lang.isEmpty()) return this
    val cfg = Configuration(resources.configuration)
    val loc = Locale(lang)
    cfg.setLocale(loc)
    return createConfigurationContext(cfg)
}

/**
 * The only activity of the vault UI. Everything on screen can be a secret, so screenshots, the recent-apps preview and screen
 * recording are blocked (FLAG_SECURE). The vault locks when the app is left (after the delay chosen in Settings) and after idling.
 */
class MainActivity : ComponentActivity() {
    private var stoppedAt = 0L

    override fun attachBaseContext(newBase: Context) {
        super.attachBaseContext(newBase.applicationContext.let { _ -> newBase.withAppLocaleSafe() })
    }

    private fun Context.withAppLocaleSafe(): Context = try {
        val lang = getSharedPreferences("pevv_prefs", MODE_PRIVATE).getString("lang", "") ?: ""
        if (lang.isEmpty()) this else createConfigurationContext(Configuration(resources.configuration).also { it.setLocale(Locale(lang)) })
    } catch (_: Exception) { this }

    override fun onCreate(savedInstanceState: Bundle?) {
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        handleIntent(intent)
        setContent { PevvTheme { AppRoot() } }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleIntent(intent)
    }

    private fun handleIntent(i: Intent?) {
        if (i?.action == UpdateManager.ACTION_INSTALL_UPDATE) { i.action = null; pevv.scope.launch(kotlinx.coroutines.Dispatchers.IO) { pevv.updates.installReady(userInitiated = true) } }
        val data = i?.data ?: return
        if (data.scheme == "dev.pevv.app" && data.host == "auth") {
            pevv.scope.launch { try { pevv.supabase.handleLink(data); pevv.sync.pull() } catch (_: Exception) { } }
        }
    }

    override fun onStart() {
        super.onStart()
        val app = pevv
        app.vault.cancelBackgroundLock()
        val mins = app.prefs.lockMinutes
        if (stoppedAt != 0L && System.currentTimeMillis() - stoppedAt >= mins * 60_000L) app.vault.lock()
        stoppedAt = 0
        app.sync.setForeground(true)
        app.updates.foreground = true
        app.vault.touch()
    }

    override fun onStop() {
        super.onStop()
        val app = pevv
        stoppedAt = System.currentTimeMillis()
        app.sync.setForeground(false)
        app.updates.foreground = false
        if (!isChangingConfigurations) app.vault.lockAfter(app.prefs.lockMinutes * 60_000L)
        // Backgrounded: an automatic install that was waiting for the vault to be out of use may go now.
        app.updates.retryDeferred()
    }

    override fun dispatchTouchEvent(ev: MotionEvent): Boolean {
        if (ev.action == MotionEvent.ACTION_DOWN) pevv.vault.touch()
        return super.dispatchTouchEvent(ev)
    }
}
