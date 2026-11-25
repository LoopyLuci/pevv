package dev.pevv.app

import dev.pevv.app.update.ApkCheck
import dev.pevv.app.update.CheckAction
import dev.pevv.app.update.ReadyAction
import dev.pevv.app.update.ReleaseParser
import dev.pevv.app.update.Sha256Sums
import dev.pevv.app.update.UpdateMode
import dev.pevv.app.update.UpdatePolicy
import dev.pevv.app.update.Version
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.MessageDigest

class UpdateLogicTest {
    private fun v(s: String) = Version.parse(s)!!

    // ---- versions ----
    @Test fun versionOrdering() {
        assertTrue(v("0.2.0") > v("0.1.9"))
        assertTrue(v("v1.0.0") > v("0.99.99"))
        assertTrue(v("0.10.0") > v("0.9.0"))
        assertEquals(v("1.0"), v("v1.0.0"))
        assertFalse(v("0.1.0") > v("0.1.0"))
    }

    @Test fun preReleaseIsOlderThanItsRelease() {
        assertTrue(v("0.2.0") > v("0.2.0-rc.1"))
        assertTrue(v("0.2.0-rc.2") > v("0.2.0-rc.1"))
        assertTrue(v("0.2.0-rc.10") > v("0.2.0-rc.9"))
        assertTrue(v("0.2.0-rc.1") > v("0.1.9"))
        assertTrue(v("0.2.0-rc.1").isPreRelease)
        assertFalse(v("0.2.0+build5").isPreRelease)
    }

    @Test fun versionRejectsGarbage() {
        for (s in listOf("", "v", "abc", "1..2", "1.x", "1.2.3.4.5", "1.0-", "1.0-a b")) assertNull(s, Version.parse(s))
    }

    @Test fun installedStripsDebugSuffix() {
        assertEquals(v("0.1.0"), Version.installed("0.1.0-debug"))
        assertTrue(UpdatePolicy.isNewer(Version.installed("0.1.0-debug"), v("0.1.1")))
        assertFalse(UpdatePolicy.isNewer(Version.installed("0.1.0"), v("0.1.0")))
        assertTrue(UpdatePolicy.isNewer(null, v("0.0.1")))
    }

    // ---- release JSON ----
    private fun release(tag: String, pre: Boolean = false, draft: Boolean = false, apk: String? = "pevv-android-v${tag.trimStart('v')}.apk", sums: Boolean = true, url: String = "https://github.com/x/releases/download/$tag/") =
        buildString {
            append("""{"tag_name":"$tag","prerelease":$pre,"draft":$draft,"assets":[""")
            val a = ArrayList<String>()
            if (apk != null) a.add("""{"name":"$apk","size":1234,"browser_download_url":"$url$apk"}""")
            if (sums) a.add("""{"name":"SHA256SUMS","size":200,"browser_download_url":"${url}SHA256SUMS"}""")
            a.add("""{"name":"pevv-desktop.exe","browser_download_url":"${url}pevv-desktop.exe"}""")
            append(a.joinToString(","))
            append("]}")
        }

    @Test fun parsesLatestRelease() {
        val r = ReleaseParser.parseLatest(release("v0.2.0"))!!
        assertEquals("v0.2.0", r.tag)
        assertEquals(v("0.2.0"), r.version)
        assertEquals("pevv-android-v0.2.0.apk", r.apkName)
        assertEquals(1234L, r.apkSize)
        assertTrue(r.apkUrl.endsWith("/pevv-android-v0.2.0.apk"))
        assertTrue(r.sumsUrl.endsWith("/SHA256SUMS"))
    }

    @Test fun rejectsReleasesWeCannotUse() {
        assertNull(ReleaseParser.parseLatest(release("v0.2.0", apk = null)))
        assertNull(ReleaseParser.parseLatest(release("v0.2.0", sums = false)))
        assertNull(ReleaseParser.parseLatest(release("v0.2.0", draft = true)))
        assertNull(ReleaseParser.parseLatest(release("v0.2.0", apk = "pevv-android-v0.3.0.apk")))
        assertNull(ReleaseParser.parseLatest(release("v0.2.0", url = "http://example.com/")))
        assertNull(ReleaseParser.parseLatest(release("nightly")))
        assertNull(ReleaseParser.parseLatest("not json"))
        assertNull(ReleaseParser.parseLatest("[]"))
        assertNull(ReleaseParser.parseLatest(release("v0.3.0-rc.1", pre = true)))
    }

    @Test fun preReleasesOnlyWhenAsked() {
        val list = "[" + listOf(release("v0.3.0-rc.1", pre = true), release("v0.2.0"), release("v0.1.0"), release("v0.4.0", draft = true)).joinToString(",") + "]"
        assertEquals("v0.2.0", ReleaseParser.parseList(list, includePre = false)!!.tag)
        assertEquals("v0.3.0-rc.1", ReleaseParser.parseList(list, includePre = true)!!.tag)
        assertNull(ReleaseParser.parseList("[" + release("v0.3.0-rc.1", pre = true) + "]", includePre = false))
        assertNull(ReleaseParser.parseList("{}", includePre = true))
    }

    // ---- SHA256SUMS ----
    private fun sha(b: ByteArray) = Sha256Sums.hex(MessageDigest.getInstance("SHA-256").digest(b))

    @Test fun sumsParseAndMatch() {
        val bytes = "apk bytes".toByteArray()
        val h = sha(bytes)
        val text = "$h  pevv-android-v0.2.0.apk\n${"A".repeat(64)} *other.zip\r\nnot a line\n"
        val sums = Sha256Sums.parse(text)
        assertEquals(2, sums.size)
        assertEquals("a".repeat(64), sums["other.zip"])
        assertTrue(Sha256Sums.matches(sums, "pevv-android-v0.2.0.apk", h))
        assertTrue(Sha256Sums.matches(sums, "pevv-android-v0.2.0.apk", h.uppercase()))
    }

    @Test fun sumsRejectMismatches() {
        val h = sha("apk bytes".toByteArray())
        val sums = Sha256Sums.parse("$h  pevv-android-v0.2.0.apk\n")
        assertFalse(Sha256Sums.matches(sums, "pevv-android-v0.2.0.apk", sha("tampered".toByteArray())))
        assertFalse(Sha256Sums.matches(sums, "pevv-android-v0.3.0.apk", h))
        assertFalse(Sha256Sums.matches(emptyMap(), "pevv-android-v0.2.0.apk", h))
        assertTrue(Sha256Sums.parse("short  file.apk").isEmpty())
    }

    // ---- APK checks ----
    @Test fun apkCheck() {
        val s = setOf("aa")
        assertNull(ApkCheck.reject("dev.pevv.app", "dev.pevv.app", 2, 1, s, s))
        assertEquals("package", ApkCheck.reject("evil.app", "dev.pevv.app", 2, 1, s, s))
        assertEquals("package", ApkCheck.reject(null, "dev.pevv.app", 2, 1, s, s))
        assertEquals("version", ApkCheck.reject("dev.pevv.app", "dev.pevv.app", 1, 1, s, s))
        assertEquals("version", ApkCheck.reject("dev.pevv.app", "dev.pevv.app", 1, 5, s, s))
        assertEquals("signature", ApkCheck.reject("dev.pevv.app", "dev.pevv.app", 2, 1, setOf("bb"), s))
        assertEquals("signature", ApkCheck.reject("dev.pevv.app", "dev.pevv.app", 2, 1, setOf("aa", "bb"), s))
        assertEquals("signature", ApkCheck.reject("dev.pevv.app", "dev.pevv.app", 2, 1, emptySet(), s))
        assertEquals("signature", ApkCheck.reject("dev.pevv.app", "dev.pevv.app", 2, 1, s, emptySet()))
    }

    // ---- modes and decisions ----
    @Test fun modeDefaultsToManual() {
        assertEquals(UpdateMode.MANUAL, UpdateMode.fromKey(null))
        assertEquals(UpdateMode.MANUAL, UpdateMode.fromKey("garbage"))
        for (m in UpdateMode.entries) assertEquals(m, UpdateMode.fromKey(m.key))
    }

    @Test fun decisionAfterCheck() {
        val man = UpdateMode.MANUAL
        assertEquals(CheckAction.NOTIFY_AVAILABLE, UpdatePolicy.afterCheck(man, true, false, false, true))
        assertEquals(CheckAction.NONE, UpdatePolicy.afterCheck(man, true, false, true, true))
        assertEquals(CheckAction.NONE, UpdatePolicy.afterCheck(man, true, false, false, false))
        assertEquals(CheckAction.NONE, UpdatePolicy.afterCheck(man, false, false, false, true))
        for (m in listOf(UpdateMode.AUTO_DOWNLOAD, UpdateMode.AUTO_INSTALL)) {
            assertEquals(CheckAction.DOWNLOAD, UpdatePolicy.afterCheck(m, true, false, false, true))
            assertEquals(CheckAction.DOWNLOAD, UpdatePolicy.afterCheck(m, true, false, true, false))
            assertEquals(CheckAction.NONE, UpdatePolicy.afterCheck(m, true, true, false, true))
            assertEquals(CheckAction.NONE, UpdatePolicy.afterCheck(m, false, false, false, true))
        }
    }

    @Test fun decisionAfterDownload() {
        assertEquals(ReadyAction.NOTIFY_READY, UpdatePolicy.afterDownload(UpdateMode.MANUAL, true))
        assertEquals(ReadyAction.NOTIFY_READY, UpdatePolicy.afterDownload(UpdateMode.AUTO_DOWNLOAD, true))
        assertEquals(ReadyAction.INSTALL_NOW, UpdatePolicy.afterDownload(UpdateMode.AUTO_INSTALL, true))
        assertEquals(ReadyAction.DEFER_AND_NOTIFY, UpdatePolicy.afterDownload(UpdateMode.AUTO_INSTALL, false))
    }

    @Test fun silentInstallNeedsAndroid12AndInstallerOfRecord() {
        assertTrue(UpdatePolicy.silentInstallPossible(31, "dev.pevv.app", "dev.pevv.app"))
        assertTrue(UpdatePolicy.silentInstallPossible(35, "dev.pevv.app", "dev.pevv.app"))
        assertFalse(UpdatePolicy.silentInstallPossible(30, "dev.pevv.app", "dev.pevv.app"))
        assertFalse(UpdatePolicy.silentInstallPossible(34, "com.android.chrome", "dev.pevv.app"))
        assertFalse(UpdatePolicy.silentInstallPossible(34, null, "dev.pevv.app"))
    }

    // ---- deferral ----
    @Test fun neverInstallsAutomaticallyWhileVaultInUseOnScreen() {
        assertFalse(UpdatePolicy.installAllowedNow(userInitiated = false, vaultInUse = true, appForeground = true))
        assertTrue(UpdatePolicy.installAllowedNow(false, vaultInUse = true, appForeground = false))   // backgrounded
        assertTrue(UpdatePolicy.installAllowedNow(false, vaultInUse = false, appForeground = true))   // locked
        assertTrue(UpdatePolicy.installAllowedNow(false, vaultInUse = false, appForeground = false))
        assertTrue(UpdatePolicy.installAllowedNow(true, vaultInUse = true, appForeground = true))     // the user tapped
        assertNotNull(UpdatePolicy)
    }
}
