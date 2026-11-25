package dev.pevv.app.update

import android.content.Context

/** Update settings and state. Non-secret; kept apart from the vault settings. */
class UpdatePrefs(ctx: Context) {
    private val sp = ctx.applicationContext.getSharedPreferences("pevv_update", Context.MODE_PRIVATE)

    var mode: UpdateMode
        get() = UpdateMode.fromKey(sp.getString("mode", null))
        set(v) = sp.edit().putString("mode", v.key).apply()

    var includePreReleases: Boolean
        get() = sp.getBoolean("pre", false)
        set(v) = sp.edit().putBoolean("pre", v).apply()

    /** Background downloads only on an unmetered network (default on). */
    var unmeteredOnly: Boolean
        get() = sp.getBoolean("unmetered", true)
        set(v) = sp.edit().putBoolean("unmetered", v).apply()

    var lastCheck: Long
        get() = sp.getLong("last_check", 0L)
        set(v) = sp.edit().putLong("last_check", v).apply()

    var lastError: String
        get() = sp.getString("last_error", "") ?: ""
        set(v) = sp.edit().putString("last_error", v).apply()

    /** Tag of the newest release we told the user about (manual mode notifies once per release). */
    var notifiedTag: String
        get() = sp.getString("notified", "") ?: ""
        set(v) = sp.edit().putString("notified", v).apply()

    /** A downloaded and verified APK waiting to be installed: file name, tag, versionCode and the SHA-256 it was verified against. */
    data class Ready(val file: String, val tag: String, val versionCode: Long, val sha256: String)

    var ready: Ready?
        get() {
            val f = sp.getString("ready_file", null) ?: return null
            return Ready(f, sp.getString("ready_tag", "") ?: "", sp.getLong("ready_code", 0L), sp.getString("ready_sha", "") ?: "")
        }
        set(v) {
            val e = sp.edit()
            if (v == null) e.remove("ready_file").remove("ready_tag").remove("ready_code").remove("ready_sha")
            else e.putString("ready_file", v.file).putString("ready_tag", v.tag).putLong("ready_code", v.versionCode).putString("ready_sha", v.sha256)
            e.apply()
        }
}
