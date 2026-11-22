package dev.pevv.app

import dev.pevv.app.autofill.AssetLinks
import dev.pevv.app.autofill.Matching
import dev.pevv.app.core.Entry
import dev.pevv.app.core.jstr
import kotlinx.serialization.json.JsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** The autofill matching rules (AGENTS.md invariant 4) and the Digital Asset Links check. No Android classes are needed. */
class MatchingTest {
    private fun login(id: String, site: String?, user: String = "me", pass: String = "pw"): Entry {
        val m = LinkedHashMap<String, kotlinx.serialization.json.JsonElement>()
        m["type"] = jstr("login")
        m["title"] = jstr(id)
        if (site != null) m["site"] = jstr(site)
        m["username"] = jstr(user)
        m["password"] = jstr(pass)
        return Entry(id, 1, JsonObject(m))
    }

    @Test fun exactHostMatchesWithDefaultScheme() {
        assertTrue(Matching.webMatches("https://example.com/login", "example.com", null))
        assertTrue(Matching.webMatches("example.com", "example.com", "https"))
        assertTrue(Matching.webMatches("https://EXAMPLE.com", "example.com.", "https"))
    }

    @Test fun neverSubdomainSiblingOrLookalike() {
        assertFalse(Matching.webMatches("https://example.com", "www.example.com", "https"))
        assertFalse(Matching.webMatches("https://www.example.com", "example.com", "https"))
        assertFalse(Matching.webMatches("https://example.com", "example.com.evil.test", "https"))
        assertFalse(Matching.webMatches("https://example.com", "evil-example.com", "https"))
        assertFalse(Matching.webMatches("https://example.com", "example.org", "https"))
    }

    @Test fun schemeAndPortMustAgree() {
        assertFalse(Matching.webMatches("http://example.com", "example.com", "https"))
        assertFalse(Matching.webMatches("https://example.com:8443", "example.com", "https"))
        assertTrue(Matching.webMatches("https://example.com:443", "example.com", "https"))
        assertTrue(Matching.webMatches("http://example.com", "example.com", "http"))
    }

    @Test fun nonWebSitesNeverMatch() {
        assertNull(Matching.parseOrigin("luciverse:thing"))
        assertNull(Matching.parseOrigin("android://abc"))
        assertNull(Matching.parseOrigin("ftp://example.com"))
        assertNull(Matching.parseOrigin(""))
        assertNull(Matching.parseOrigin(null))
    }

    @Test fun forWebFiltersLogins() {
        val list = listOf(login("a", "https://example.com"), login("b", "https://www.example.com"), login("c", null))
        assertEquals(listOf("a"), Matching.forWeb(list, "example.com", "https").map { it.id })
    }

    @Test fun forAppUsesLinksAndVerifiedHostsOnly() {
        val list = listOf(login("a", "https://example.com"), login("b", "https://other.org"), login("c", null))
        assertEquals(emptyList<String>(), Matching.forApp(list, "com.example.app", emptyMap(), emptySet()).map { it.id })
        assertEquals(listOf("c"), Matching.forApp(list, "com.example.app", mapOf("com.example.app" to "c"), emptySet()).map { it.id })
        assertEquals(listOf("a"), Matching.forApp(list, "com.example.app", emptyMap(), setOf("example.com")).map { it.id })
        // a link for another package does not apply
        assertEquals(emptyList<String>(), Matching.forApp(list, "com.example.app", mapOf("com.other" to "c"), emptySet()).map { it.id })
    }

    @Test fun candidateDomainFromPackage() {
        assertEquals("example.com", Matching.candidateDomain("com.example.app"))
        assertEquals("example.org", Matching.candidateDomain("org.example.mail.client"))
        assertNull(Matching.candidateDomain("single"))
        assertNull(Matching.candidateDomain("xyz.example.app"))
        assertTrue(Matching.hostBelongsTo("login.example.com", "example.com"))
        assertFalse(Matching.hostBelongsTo("badexample.com", "example.com"))
    }

    private val doc = """
        [{"relation":["delegate_permission/common.get_login_creds"],
          "target":{"namespace":"android_app","package_name":"com.example.app","sha256_cert_fingerprints":["aa:bb:cc"]}},
         {"relation":["delegate_permission/common.handle_all_urls"],
          "target":{"namespace":"android_app","package_name":"com.other.app","sha256_cert_fingerprints":["11:22:33"]}}]
    """.trimIndent()

    @Test fun assetLinksNeedsPackageCertAndRelation() {
        assertTrue(AssetLinks.check(doc, "com.example.app", setOf("AA:BB:CC")))
        assertFalse(AssetLinks.check(doc, "com.example.app", setOf("DD:EE:FF")))
        assertFalse(AssetLinks.check(doc, "com.evil.app", setOf("AA:BB:CC")))
        // right package, wrong relation
        assertFalse(AssetLinks.check(doc, "com.other.app", setOf("11:22:33")))
        assertTrue(AssetLinks.check(doc, "com.other.app", setOf("11:22:33"), "delegate_permission/common.handle_all_urls"))
    }

    @Test fun assetLinksRejectsGarbage() {
        assertFalse(AssetLinks.check("not json", "com.example.app", setOf("AA:BB:CC")))
        assertFalse(AssetLinks.check("{}", "com.example.app", setOf("AA:BB:CC")))
        assertFalse(AssetLinks.check("[]", "com.example.app", setOf("AA:BB:CC")))
        assertFalse(AssetLinks.check("[{\"relation\":1}]", "com.example.app", setOf("AA:BB:CC")))
    }
}
