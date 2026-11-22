package dev.pevv.app

import android.app.Application
import android.content.Intent
import android.content.IntentFilter
import android.content.BroadcastReceiver
import android.content.Context
import dev.pevv.app.security.BiometricVault
import dev.pevv.app.store.AppPrefs
import dev.pevv.app.store.VaultController
import dev.pevv.app.sync.Relay
import dev.pevv.app.sync.Supabase
import dev.pevv.app.sync.SyncManager
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob

/** Process-wide singletons. The autofill and credential services run in this process and use the same unlocked state. */
class PevvApp : Application() {
    val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    lateinit var prefs: AppPrefs; private set
    lateinit var vault: VaultController; private set
    lateinit var supabase: Supabase; private set
    lateinit var relay: Relay; private set
    lateinit var sync: SyncManager; private set
    lateinit var bio: BiometricVault; private set

    override fun onCreate() {
        super.onCreate()
        prefs = AppPrefs(this)
        vault = VaultController(this, prefs, scope)
        supabase = Supabase(this)
        relay = Relay(supabase)
        sync = SyncManager(this, vault, supabase, relay, scope)
        bio = BiometricVault(this)
        sync.start()
        // Screen off with "lock immediately" set: drop the key before anything else can look at the phone.
        registerReceiver(object : BroadcastReceiver() {
            override fun onReceive(c: Context, i: Intent) {
                if (prefs.lockMinutes == 0) vault.lock()
            }
        }, IntentFilter(Intent.ACTION_SCREEN_OFF))
    }
}

val Context.pevv: PevvApp get() = applicationContext as PevvApp
