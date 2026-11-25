package dev.pevv.app.update

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.longOrNull
import java.security.MessageDigest

/* Pure update logic (no Android classes), so it is unit-tested on the JVM. */

/** A release version such as `0.2.0` or `v0.3.0-rc.1`, ordered like semver (a pre-release is older than its release). */
class Version private constructor(private val nums: List<Int>, private val pre: List<String>) : Comparable<Version> {
    val isPreRelease get() = pre.isNotEmpty()

    override fun compareTo(other: Version): Int {
        for (i in 0 until maxOf(nums.size, other.nums.size)) {
            val c = nums.getOrElse(i) { 0 }.compareTo(other.nums.getOrElse(i) { 0 })
            if (c != 0) return c
        }
        if (pre.isEmpty() && other.pre.isEmpty()) return 0
        if (pre.isEmpty()) return 1
        if (other.pre.isEmpty()) return -1
        for (i in 0 until minOf(pre.size, other.pre.size)) {
            val a = pre[i]
            val b = other.pre[i]
            val an = a.toIntOrNull()
            val bn = b.toIntOrNull()
            val c = when {
                an != null && bn != null -> an.compareTo(bn)
                an != null -> -1
                bn != null -> 1
                else -> a.compareTo(b)
            }
            if (c != 0) return c
        }
        return pre.size.compareTo(other.pre.size)
    }

    override fun equals(other: Any?) = other is Version && compareTo(other) == 0
    override fun hashCode() = nums.dropLastWhile { it == 0 }.hashCode() * 31 + pre.hashCode()
    override fun toString() = nums.joinToString(".") + if (pre.isEmpty()) "" else "-" + pre.joinToString(".")

    companion object {
        /** Null when [s] is not a dotted number list with an optional `-pre.release` and `+build` part. */
        fun parse(s: String): Version? {
            var t = s.trim()
            if (t.startsWith("v") || t.startsWith("V")) t = t.substring(1)
            t = t.substringBefore('+')
            val core = t.substringBefore('-')
            val pre = if ('-' in t) t.substringAfter('-').split('.', '-') else emptyList()
            if (pre.any { it.isEmpty() || !it.all { c -> c.isLetterOrDigit() } }) return null
            val parts = core.split('.')
            if (parts.size > 4) return null
            val nums = ArrayList<Int>()
            for (p in parts) {
                if (p.isEmpty() || p.length > 9 || !p.all { it in '0'..'9' }) return null
                nums.add(p.toInt())
            }
            return Version(nums, pre)
        }

        /** The running app's version name without the build-type suffix (`0.1.0-debug` is 0.1.0). */
        fun installed(versionName: String): Version? = parse(versionName.removeSuffix("-debug"))
    }
}

/** The parts of a GitHub release the updater uses. [version] comes from the tag. */
data class ReleaseInfo(
    val tag: String,
    val version: Version,
    val preRelease: Boolean,
    val apkName: String,
    val apkUrl: String,
    val apkSize: Long,
    val sumsUrl: String,
)

object ReleaseParser {
    private val json = Json { ignoreUnknownKeys = true }

    private fun isHttps(u: String) = u.startsWith("https://") && u.length > 10 && u.none { it.isWhitespace() }

    /** One release object. Null for a draft, a bad tag, or one missing the APK or SHA256SUMS asset (or served over anything but HTTPS). */
    fun parseRelease(o: JsonObject): ReleaseInfo? {
        if ((o["draft"] as? JsonPrimitive)?.booleanOrNull == true) return null
        val tag = (o["tag_name"] as? JsonPrimitive)?.contentOrNull ?: return null
        val version = Version.parse(tag) ?: return null
        val pre = (o["prerelease"] as? JsonPrimitive)?.booleanOrNull == true || version.isPreRelease
        val assets = (o["assets"] as? JsonArray)?.mapNotNull { it as? JsonObject } ?: return null
        val wanted = "pevv-android-v${tag.trimStart('v', 'V')}.apk"
        var apk: JsonObject? = null
        var sums: JsonObject? = null
        for (a in assets) {
            val name = (a["name"] as? JsonPrimitive)?.contentOrNull ?: continue
            if (name == wanted) apk = a
            if (name == "SHA256SUMS") sums = a
        }
        val apkUrl = (apk?.get("browser_download_url") as? JsonPrimitive)?.contentOrNull ?: return null
        val sumsUrl = (sums?.get("browser_download_url") as? JsonPrimitive)?.contentOrNull ?: return null
        if (!isHttps(apkUrl) || !isHttps(sumsUrl)) return null
        val size = (apk?.get("size") as? JsonPrimitive)?.longOrNull ?: 0L
        return ReleaseInfo(tag, version, pre, wanted, apkUrl, size, sumsUrl)
    }

    /** The `releases/latest` response (a single object). GitHub never returns a pre-release there; one is refused anyway. */
    fun parseLatest(text: String): ReleaseInfo? = try {
        (json.parseToJsonElement(text) as? JsonObject)?.let { parseRelease(it) }?.takeIf { !it.preRelease }
    } catch (_: Exception) { null }

    /** The `releases` list: the newest usable release, skipping pre-releases unless [includePre]. */
    fun parseList(text: String, includePre: Boolean): ReleaseInfo? = try {
        val arr = json.parseToJsonElement(text) as? JsonArray
        arr?.mapNotNull { (it as? JsonObject)?.let { o -> parseRelease(o) } }
            ?.filter { includePre || !it.preRelease }
            ?.maxByOrNull { it.version }
    } catch (_: Exception) { null }
}

object Sha256Sums {
    private val line = Regex("^([0-9a-fA-F]{64})[ \\t]+\\*?(.+)$")

    /** `sha256sum` output: `<hex>  <file name>` per line. Later lines for the same name win; bad lines are ignored. */
    fun parse(text: String): Map<String, String> {
        val out = LinkedHashMap<String, String>()
        for (raw in text.lineSequence()) {
            val m = line.matchEntire(raw.trim()) ?: continue
            out[m.groupValues[2].trim()] = m.groupValues[1].lowercase()
        }
        return out
    }

    fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }

    /** True only when SHA256SUMS lists [fileName] and its hash equals [actualHex] (compared without early exit). */
    fun matches(sums: Map<String, String>, fileName: String, actualHex: String): Boolean {
        val want = sums[fileName] ?: return false
        return MessageDigest.isEqual(want.lowercase().toByteArray(), actualHex.lowercase().toByteArray())
    }
}

enum class UpdateMode(val key: String) {
    /** Check and notify only; the user taps to download and install. */
    MANUAL("manual"),
    /** Download in the background, then notify "ready, tap to install". */
    AUTO_DOWNLOAD("auto_download"),
    /** Download in the background and install through a PackageInstaller session. */
    AUTO_INSTALL("auto_install");

    companion object {
        fun fromKey(k: String?): UpdateMode = entries.firstOrNull { it.key == k } ?: MANUAL
    }
}

enum class CheckAction { NONE, NOTIFY_AVAILABLE, DOWNLOAD }
enum class ReadyAction { NOTIFY_READY, INSTALL_NOW, DEFER_AND_NOTIFY }

object UpdatePolicy {
    /** Name-based pre-filter; the real gate is the APK's versionCode ([ApkCheck]). */
    fun isNewer(installed: Version?, candidate: Version): Boolean = installed == null || candidate > installed

    /** What to do after a check found [newer] (or not). [background] is false for the "Check now" button. */
    fun afterCheck(mode: UpdateMode, newer: Boolean, readyForThisVersion: Boolean, alreadyNotified: Boolean, background: Boolean): CheckAction = when {
        !newer || readyForThisVersion -> CheckAction.NONE
        mode == UpdateMode.MANUAL -> if (background && !alreadyNotified) CheckAction.NOTIFY_AVAILABLE else CheckAction.NONE
        else -> CheckAction.DOWNLOAD
    }

    /** What to do once a verified APK is on disk. */
    fun afterDownload(mode: UpdateMode, installAllowedNow: Boolean): ReadyAction = when (mode) {
        UpdateMode.AUTO_INSTALL -> if (installAllowedNow) ReadyAction.INSTALL_NOW else ReadyAction.DEFER_AND_NOTIFY
        else -> ReadyAction.NOTIFY_READY
    }

    /**
     * The deferral rule: never replace the app while the vault is unlocked and on screen. A tap by the user is an explicit
     * request and goes ahead; an automatic install waits until the vault is locked or the app is in the background.
     */
    fun installAllowedNow(userInitiated: Boolean, vaultInUse: Boolean, appForeground: Boolean): Boolean =
        userInitiated || !(vaultInUse && appForeground)

    /** Silent (no prompt) updates need Android 12+ and this app to be the installer of record of itself. */
    fun silentInstallPossible(sdk: Int, installerPackage: String?, ownPackage: String): Boolean =
        sdk >= 31 && installerPackage == ownPackage
}

object ApkCheck {
    /** Null when the downloaded APK may be installed, otherwise the reason it is rejected. */
    fun reject(
        apkPackage: String?, ownPackage: String,
        apkVersionCode: Long, installedVersionCode: Long,
        apkSigners: Set<String>, ownSigners: Set<String>,
    ): String? = when {
        apkPackage != ownPackage -> "package"
        apkVersionCode <= installedVersionCode -> "version"
        apkSigners.isEmpty() || ownSigners.isEmpty() -> "signature"
        apkSigners != ownSigners -> "signature"
        else -> null
    }
}
