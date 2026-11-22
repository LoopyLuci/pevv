package dev.pevv.app.core

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class ImportResult(val source: String, val entries: List<JsonObject>, val skipped: Int)

/** Import of password-manager exports: a port of `importManagerExport` and friends in src/pevv/extra.ts. */
object Import {
    /** RFC 4180 CSV (quoted fields, "" escapes, CRLF, embedded newlines). */
    fun parseCsv(text: String): List<List<String>> {
        val rows = ArrayList<List<String>>()
        var row = ArrayList<String>()
        val field = StringBuilder()
        var q = false
        val s = text.removePrefix("\uFEFF")
        var i = 0
        while (i < s.length) {
            val c = s[i]
            if (q) {
                if (c == '"') {
                    if (i + 1 < s.length && s[i + 1] == '"') {
                        field.append('"')
                        i++
                    } else q = false
                } else field.append(c)
            } else if (c == '"' && field.isEmpty()) q = true
            else if (c == ',') {
                row.add(field.toString())
                field.clear()
            } else if (c == '\n' || c == '\r') {
                if (c == '\r' && i + 1 < s.length && s[i + 1] == '\n') i++
                row.add(field.toString())
                field.clear()
                if (row.size > 1 || row[0] != "") rows.add(row)
                row = ArrayList()
            } else field.append(c)
            i++
        }
        if (field.isNotEmpty() || row.isNotEmpty()) {
            row.add(field.toString())
            if (row.size > 1 || row[0] != "") rows.add(row)
        }
        return rows
    }

    private fun truthy(v: String?) = Regex("^(1|true|yes|y)$", RegexOption.IGNORE_CASE).matches((v ?: "").trim())

    private fun hostOf(url: String): String = try {
        val u = if (Regex("^[a-z][a-z0-9+.-]*:", RegexOption.IGNORE_CASE).containsMatchIn(url)) url else "https://$url"
        java.net.URI(u).host ?: ""
    } catch (_: Exception) {
        ""
    }

    private fun newItem(type: String, now: Long): LinkedHashMap<String, JsonElement> = LinkedHashMap(EntryKinds.newData(type, now))

    private fun JsonObject.rec(k: String): JsonObject? = this[k] as? JsonObject

    private fun JsonElement?.s(): String = ((this as? JsonPrimitive)?.takeIf { it.isString }?.content ?: "").trim()

    private fun JsonElement?.asObj(): JsonObject? = this as? JsonObject

    fun importCsv(text: String, now: Long = System.currentTimeMillis()): ImportResult {
        val rows = parseCsv(text)
        if (rows.size < 2) return ImportResult("generic", emptyList(), 0)
        val head = rows[0].map { it.trim().lowercase() }
        fun col(vararg names: String): Int {
            for (n in names) {
                val i = head.indexOf(n)
                if (i >= 0) return i
            }
            return -1
        }
        fun has(vararg names: String) = names.all { it in head }
        val source = when {
            has("login_uri", "login_username") -> "bitwarden"
            has("title", "url", "username", "password") && ("otpauth" in head || "archived" in head || "tags" in head) -> "1password"
            has("type", "name", "url", "email", "username", "password") -> "proton"
            has("url", "username", "password", "extra", "grouping") -> "lastpass"
            has("url", "username", "password", "httprealm") -> "firefox"
            has("title", "url", "username", "password", "otpauth") -> "safari"
            has("group", "title", "username", "password", "url") -> "keepass"
            has("title", "password", "url") && ("otpsecret" in head || "username2" in head) -> "dashlane"
            "cardholdername" in head && has("name", "url", "username", "password") -> "nordpass"
            has("name", "url", "username", "password") -> "chrome"
            else -> "generic"
        }
        val iTitle = col("name", "title")
        val iUrl = col("login_uri", "url", "website", "uri", "origin")
        val iUser = col("login_username", "username", "user", "login")
        val iEmail = col("email", "itememail")
        val iPass = col("login_password", "password", "pass")
        val iTotp = col("login_totp", "otpauth", "totp", "otp", "otpsecret")
        val iNotes = col("notes", "note", "extra", "comments")
        val iFolder = col("folder", "grouping", "group", "vault")
        val iFav = col("favorite", "fav")
        val iTags = col("tags")
        val iType = col("type")
        val iArch = col("archived")
        val iCard = col("cardnumber", "number")
        val iCvv = col("cvc", "cvv", "verificationnumber")
        val iExp = col("expirydate", "expiry", "expirationdate")
        val iHolder = col("cardholdername", "cardholder")
        val known = listOf(
            iTitle, iUrl, iUser, iEmail, iPass, iTotp, iNotes, iFolder, iFav, iTags, iType, iArch, iCard, iCvv, iExp, iHolder, col("reprompt"), col("fields"),
            col("httprealm"), col("formactionorigin"), col("guid"), col("timecreated"), col("timelastused"), col("timepasswordchanged"), col("createtime"),
            col("modifytime"), col("username2"), col("username3"), col("category"),
        ).filter { it >= 0 }.toSet()
        val entries = ArrayList<JsonObject>()
        var skipped = 0
        for (r in rows.drop(1)) {
            fun g(i: Int) = if (i >= 0) (r.getOrNull(i) ?: "").trim() else ""
            val kind = g(iType).lowercase()
            val pass = if (iPass >= 0) (r.getOrNull(iPass) ?: "") else ""
            val user = g(iUser).ifEmpty { g(iEmail) }
            val cardNumber = g(iCard).replace(Regex("\\s+"), "")
            if (cardNumber.isNotEmpty()) {
                val e = newItem("card", now)
                e["title"] = jstr((g(iTitle).ifEmpty { "Card" }).take(120))
                e["number"] = jstr(cardNumber)
                if (g(iHolder).isNotEmpty()) e["cardholder"] = jstr(g(iHolder))
                if (g(iCvv).isNotEmpty()) e["cvv"] = jstr(g(iCvv))
                val exp = g(iExp)
                val expiry = if (Regex("^\\d{4}$").matches(exp)) "${exp.take(2)}/${exp.substring(2)}" else exp
                if (expiry.isNotEmpty()) e["expiry"] = jstr(expiry)
                if (g(iFolder).isNotEmpty() && g(iFolder) != "(none)") e["folder"] = jstr(g(iFolder).take(40))
                e["tags"] = jstrs(listOf("imported"))
                entries.add(JsonObject(e))
                if (pass.isEmpty() && user.isEmpty()) continue
            }
            val isNote = kind == "note" || kind == "securenote" || (pass.isEmpty() && user.isEmpty() && g(iUrl).isEmpty() && g(iNotes).isNotEmpty())
            if (pass.isEmpty() && user.isEmpty() && g(iUrl).isEmpty() && g(iNotes).isEmpty() && g(iTitle).isEmpty()) {
                skipped++
                continue
            }
            if (kind.isNotEmpty() && kind !in listOf("login", "alias", "note", "securenote")) {
                skipped++
                continue
            }
            val e = newItem(if (isNote) "note" else "login", now)
            val host = if (g(iUrl).isNotEmpty()) hostOf(g(iUrl)) else ""
            e["title"] = jstr((g(iTitle).ifEmpty { host.ifEmpty { user.ifEmpty { "Imported" } } }).take(120))
            if (!isNote) {
                if (g(iUrl).isNotEmpty()) e["site"] = jstr(g(iUrl))
                if (user.isNotEmpty()) e["username"] = jstr(user)
                if (pass.isNotEmpty()) e["password"] = jstr(pass)
                if (g(iTotp).isNotEmpty()) e["totp"] = jstr(g(iTotp))
            }
            val emailNote = if (g(iEmail).isNotEmpty() && g(iEmail) != user) "Email: ${g(iEmail)}" else ""
            val extra = r.mapIndexed { i, v -> if (i !in known && v.trim().isNotEmpty()) "${rows[0].getOrNull(i)}: ${v.trim()}" else "" }.filter { it.isNotEmpty() }
            val notes = (listOf(if (iNotes >= 0) (r.getOrNull(iNotes) ?: "") else "", emailNote) + extra).filter { it.trim().isNotEmpty() }.joinToString("\n")
            if (notes.isNotEmpty()) e["notes"] = jstr(notes)
            if (g(iFolder).isNotEmpty() && g(iFolder) != "(none)") e["folder"] = jstr(g(iFolder).take(40))
            if (truthy(g(iFav))) e["favorite"] = jbool(true)
            val tags = g(iTags).split(Regex("[;,]")).map { it.trim() }.filter { it.isNotEmpty() }.toMutableList()
            if (truthy(g(iArch))) tags.add("archived")
            e["tags"] = jstrs((listOf("imported") + tags).distinct().take(20))
            entries.add(JsonObject(e))
        }
        return ImportResult(source, entries, skipped)
    }

    fun importProtonJson(text: String, now: Long = System.currentTimeMillis()): ImportResult? {
        val root = try { Json.parse(text) as? JsonObject } catch (_: Exception) { null } ?: return null
        val vaults = root.rec("vaults") ?: return null
        val entries = ArrayList<JsonObject>()
        var skipped = 0
        for (vault in vaults.values) {
            val v = vault.asObj() ?: continue
            val folder = v["name"].s().take(40)
            val items = (v["items"] as? JsonArray) ?: JsonArray(emptyList())
            for (item in items) {
                val data = item.asObj()?.rec("data")
                if (data == null) { skipped++; continue }
                val meta = data.rec("metadata")
                val content = data.rec("content") ?: JsonObject(emptyMap())
                val type = data["type"].s()
                val title = ((meta?.get("name").s()).ifEmpty { "Imported" }).take(120)
                val note = meta?.get("note").s()
                when (type) {
                    "login", "alias" -> {
                        val e = newItem("login", now)
                        e["title"] = jstr(title)
                        val urls = ((content["urls"] as? JsonArray) ?: JsonArray(emptyList())).map { it.s() }.filter { it.isNotEmpty() }
                        if (urls.isNotEmpty()) e["site"] = jstr(urls[0])
                        val user = content["itemUsername"].s().ifEmpty { content["itemEmail"].s() }
                        if (user.isNotEmpty()) e["username"] = jstr(user)
                        if (content["password"].s().isNotEmpty()) e["password"] = jstr(content["password"].s())
                        if (content["totpUri"].s().isNotEmpty()) e["totp"] = jstr(content["totpUri"].s())
                        val bits = listOf(
                            note,
                            if (content["itemEmail"].s().isNotEmpty() && content["itemEmail"].s() != user) "Email: ${content["itemEmail"].s()}" else "",
                            urls.drop(1).joinToString("\n"),
                        ).filter { it.isNotEmpty() }
                        if (bits.isNotEmpty()) e["notes"] = jstr(bits.joinToString("\n"))
                        if (folder.isNotEmpty()) e["folder"] = jstr(folder)
                        e["tags"] = jstrs(listOf("imported"))
                        if (e["password"] == null && e["username"] == null && e["site"] == null && e["notes"] == null) { skipped++; continue }
                        entries.add(JsonObject(e))
                    }
                    "note" -> {
                        val e = newItem("note", now)
                        e["title"] = jstr(title)
                        if (note.isNotEmpty()) e["notes"] = jstr(note)
                        if (folder.isNotEmpty()) e["folder"] = jstr(folder)
                        e["tags"] = jstrs(listOf("imported"))
                        entries.add(JsonObject(e))
                    }
                    "creditCard" -> {
                        val e = newItem("card", now)
                        e["title"] = jstr(title)
                        e["cardholder"] = jstr(content["cardholderName"].s())
                        e["number"] = jstr(content["number"].s().replace(Regex("\\s+"), ""))
                        e["cvv"] = jstr(content["verificationNumber"].s())
                        val exp = content["expirationDate"].s()
                        e["expiry"] = jstr(if (Regex("^\\d{4}$").matches(exp)) "${exp.take(2)}/${exp.substring(2)}" else exp)
                        if (content["pin"].s().isNotEmpty()) e["pin"] = jstr(content["pin"].s())
                        if (note.isNotEmpty()) e["notes"] = jstr(note)
                        if (folder.isNotEmpty()) e["folder"] = jstr(folder)
                        e["tags"] = jstrs(listOf("imported"))
                        if ((e["number"] as JsonPrimitive).content.isEmpty() && (e["cardholder"] as JsonPrimitive).content.isEmpty()) { skipped++; continue }
                        entries.add(JsonObject(e))
                    }
                    else -> skipped++
                }
            }
        }
        return ImportResult("proton", entries, skipped)
    }

    fun importBitwardenJson(text: String, now: Long = System.currentTimeMillis()): ImportResult? {
        val root = try { Json.parse(text) as? JsonObject } catch (_: Exception) { null } ?: return null
        val items = root["items"] as? JsonArray ?: return null
        val folders = HashMap<String, String>()
        (root["folders"] as? JsonArray)?.forEach { f ->
            val fr = f.asObj()
            if (fr != null && fr["id"].s().isNotEmpty()) folders[fr["id"].s()] = fr["name"].s().take(40)
        }
        val entries = ArrayList<JsonObject>()
        var skipped = 0
        for (item in items) {
            val it = item.asObj()
            if (it == null) { skipped++; continue }
            val type = (it["type"] as? JsonPrimitive)?.takeIf { p -> !p.isString }?.content?.toDoubleOrNull()?.toInt() ?: -1
            val title = (it["name"].s().ifEmpty { "Imported" }).take(120)
            val note = it["notes"].s()
            val folder = folders[it["folderId"].s()] ?: ""
            when (type) {
                1 -> {
                    val login = it.rec("login") ?: JsonObject(emptyMap())
                    val e = newItem("login", now)
                    e["title"] = jstr(title)
                    val uri = (login["uris"] as? JsonArray)?.firstOrNull().asObj()?.get("uri").s()
                    if (!uri.isNullOrEmpty()) e["site"] = jstr(uri)
                    if (login["username"].s().isNotEmpty()) e["username"] = jstr(login["username"].s())
                    if (login["password"].s().isNotEmpty()) e["password"] = jstr(login["password"].s())
                    if (login["totp"].s().isNotEmpty()) e["totp"] = jstr(login["totp"].s())
                    if (note.isNotEmpty()) e["notes"] = jstr(note)
                    if (folder.isNotEmpty()) e["folder"] = jstr(folder)
                    e["tags"] = jstrs(listOf("imported"))
                    entries.add(JsonObject(e))
                }
                2 -> {
                    val e = newItem("note", now)
                    e["title"] = jstr(title)
                    if (note.isNotEmpty()) e["notes"] = jstr(note)
                    if (folder.isNotEmpty()) e["folder"] = jstr(folder)
                    e["tags"] = jstrs(listOf("imported"))
                    entries.add(JsonObject(e))
                }
                3 -> {
                    val card = it.rec("card") ?: JsonObject(emptyMap())
                    val e = newItem("card", now)
                    e["title"] = jstr(title)
                    e["cardholder"] = jstr(card["cardholderName"].s())
                    e["number"] = jstr(card["number"].s().replace(Regex("\\s+"), ""))
                    e["cvv"] = jstr(card["code"].s())
                    val month = card["expMonth"].s()
                    val year = card["expYear"].s()
                    if (month.isNotEmpty() && year.isNotEmpty()) e["expiry"] = jstr("${month.padStart(2, '0')}/${year.takeLast(2)}")
                    if (note.isNotEmpty()) e["notes"] = jstr(note)
                    if (folder.isNotEmpty()) e["folder"] = jstr(folder)
                    e["tags"] = jstrs(listOf("imported"))
                    if ((e["number"] as JsonPrimitive).content.isEmpty() && (e["cardholder"] as JsonPrimitive).content.isEmpty()) { skipped++; continue }
                    entries.add(JsonObject(e))
                }
                else -> skipped++
            }
        }
        return ImportResult("bitwarden", entries, skipped)
    }

    /** CSV, or an unencrypted Proton Pass / Bitwarden JSON export. */
    fun importManagerExport(text: String, now: Long = System.currentTimeMillis()): ImportResult {
        val t = text.removePrefix("\uFEFF").trim()
        if (t.startsWith("-----BEGIN PGP")) throw IllegalArgumentException("This Proton Pass export is still encrypted. Export an unencrypted JSON or CSV, import it, then delete the file.")
        if (t.startsWith("{")) {
            importProtonJson(t, now)?.let { if (it.entries.isNotEmpty() || it.skipped > 0) return it }
            importBitwardenJson(t, now)?.let { if (it.entries.isNotEmpty() || it.skipped > 0) return it }
            throw IllegalArgumentException("That JSON is not an unencrypted Proton Pass or Bitwarden export.")
        }
        return importCsv(t, now)
    }

    /** .env variables as items of kind  in the given environment. */
    fun envItems(vars: List<Pair<String, String>>, env: String, now: Long = System.currentTimeMillis()): ImportResult {
        val items = vars.map { (n, v) ->
            val e = newItem("env", now)
            e["title"] = jstr(n); e["name"] = jstr(n); e["value"] = jstr(v); e["env"] = jstr(env.trim().ifEmpty { "dev" })
            e["tags"] = jstrs(listOf("imported"))
            JsonObject(e)
        }
        return ImportResult("dotenv", items, 0)
    }

    /* ---------- .env ---------- */

    val ENV_NAME = Regex("^[A-Za-z_][A-Za-z0-9_]*$")

    private fun closingQuote(s: String): Int {
        var k = 0
        while (k < s.length) {
            if (s[k] == '\\') { k += 2; continue }
            if (s[k] == '"') return k
            k++
        }
        return -1
    }

    fun parseDotenv(src: String): List<Pair<String, String>> {
        val out = ArrayList<Pair<String, String>>()
        val lines = src.replace(Regex("\r\n?"), "\n").split("\n")
        var i = 0
        while (i < lines.size) {
            var line = lines[i].trim()
            if (line.isEmpty() || line.startsWith("#")) { i++; continue }
            if (line.startsWith("export ")) line = line.substring(7).trim()
            val eq = line.indexOf('=')
            if (eq <= 0) { i++; continue }
            val name = line.substring(0, eq).trim()
            if (!ENV_NAME.matches(name)) { i++; continue }
            var value = line.substring(eq + 1).trim()
            if (value.startsWith("\"")) {
                var buf = value.substring(1)
                var close = closingQuote(buf)
                while (close < 0 && i + 1 < lines.size) {
                    buf += "\n" + lines[++i]
                    close = closingQuote(buf)
                }
                val raw = if (close < 0) buf else buf.substring(0, close)
                value = Regex("\\\\(.)", RegexOption.DOT_MATCHES_ALL).replace(raw) { m ->
                    when (val c = m.groupValues[1]) { "n" -> "\n"; "t" -> "\t"; "r" -> "\r"; else -> c }
                }
            } else if (value.startsWith("'")) {
                val end = value.indexOf("'", 1)
                value = if (end > 0) value.substring(1, end) else value.substring(1)
            } else {
                val hash = Regex("\\s#").find(value)
                if (hash != null) value = value.substring(0, hash.range.first).trim()
            }
            out.add(name to value)
            i++
        }
        return out
    }

    fun serializeDotenv(vars: List<Pair<String, String>>): String =
        vars.filter { ENV_NAME.matches(it.first) }.joinToString("\n") { (n, v) ->
            val plain = Regex("^[A-Za-z0-9_./:@+-]*$").matches(v)
            val value = if (plain) v else "\"" + v.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n") + "\""
            "$n=$value"
        } + "\n"
}
