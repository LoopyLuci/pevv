package dev.pevv.app.autofill

import dev.pevv.app.core.Entry
import java.net.URI

/**
 * Which logins may fill a form. The rule is the same one the browser extension uses (AGENTS.md invariant 4): the origin the system
 * reports must equal the saved site. Never a look-alike (`example.com.evil.test`), a sibling, or a sub-domain.
 */
object Matching {
    data class Origin(val scheme: String, val host: String, val port: Int)

    private fun defaultPort(scheme: String) = if (scheme == "https") 443 else if (scheme == "http") 80 else -1

    /** The origin of a saved site (`https://` assumed when there is no scheme). Null for anything that is not a web address. */
    fun parseOrigin(site: String?): Origin? {
        val s = site?.trim().orEmpty()
        if (s.isEmpty() || s.lowercase().startsWith("luciverse:") || s.lowercase().startsWith("android")) return null
        return try {
            val u = URI(if (Regex("^[a-z][a-z0-9+.-]*://", RegexOption.IGNORE_CASE).containsMatchIn(s)) s else "https://$s")
            val scheme = (u.scheme ?: return null).lowercase()
            if (scheme != "http" && scheme != "https") return null
            val host = (u.host ?: return null).lowercase().trimEnd('.')
            Origin(scheme, host, if (u.port == -1) defaultPort(scheme) else u.port)
        } catch (_: Exception) {
            null
        }
    }

    /**
     * `webDomain` and `webScheme` come from the browser through the autofill framework (host only, no port). A saved site matches only
     * when its host is exactly that host, its scheme is the reported one (https when none is reported) and its port is the default one.
     */
    fun webMatches(site: String?, webDomain: String, webScheme: String?): Boolean {
        val o = parseOrigin(site) ?: return false
        val scheme = (webScheme ?: "https").lowercase()
        return o.host == webDomain.trim().lowercase().trimEnd('.') && o.scheme == scheme && o.port == defaultPort(scheme)
    }

    fun logins(entries: List<Entry>) = entries.filter { it.type == "login" && !it.password.isNullOrEmpty() || it.type == "login" && !it.username.isNullOrEmpty() }

    fun forWeb(entries: List<Entry>, webDomain: String, webScheme: String?): List<Entry> =
        logins(entries).filter { webMatches(it.site, webDomain, webScheme) }

    /**
     * Native apps: a login the user linked to this package (sealed in the vault, `androidAppLinks`), or one whose site Digital Asset
     * Links says belongs to this package (`verifiedHosts` is the set of hosts that proved it).
     */
    fun forApp(entries: List<Entry>, pkg: String, links: Map<String, String>, verifiedHosts: Set<String>): List<Entry> {
        val linked = links[pkg]
        return logins(entries).filter { e -> e.id == linked || parseOrigin(e.site)?.let { it.host in verifiedHosts && it.scheme == "https" } == true }
    }

    /** Hosts a package might own, from its reverse-domain name: `com.example.app` -> `example.com`. Used only to limit lookups. */
    fun candidateDomain(pkg: String): String? {
        val parts = pkg.split('.')
        if (parts.size < 2) return null
        val tld = parts[0]
        if (tld !in setOf("com", "org", "net", "io", "app", "dev", "co", "de", "fr", "es", "uk", "me", "tv", "edu", "gov")) return null
        return "${parts[1]}.$tld"
    }

    fun hostBelongsTo(host: String, domain: String) = host == domain || host.endsWith(".$domain")
}
