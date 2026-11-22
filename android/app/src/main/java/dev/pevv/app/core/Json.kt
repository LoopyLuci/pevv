package dev.pevv.app.core

import kotlinx.serialization.json.Json as KJson
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * The vault file and every sealed record are JSON documents that other clients also write. Keeping them as
 * JsonElement trees (not fixed classes) means fields this client does not know are carried through untouched,
 * which is the compatibility rule in docs/VAULT_FORMAT.md.
 */
object Json {
    private val k = KJson { prettyPrint = false }
    private val pretty = KJson {
        prettyPrint = true
        prettyPrintIndent = "  "
    }

    /** Compact output, like JSON.stringify. */
    fun encode(e: JsonElement): String = k.encodeToString(JsonElement.serializer(), e)

    fun encodePretty(e: JsonElement): String = pretty.encodeToString(JsonElement.serializer(), e)

    fun parse(s: String): JsonElement = k.parseToJsonElement(s)

    fun parseObject(s: String): JsonObject = parse(s) as? JsonObject ?: throw IllegalArgumentException("not a JSON object")
}

fun JsonObject.str(key: String): String? = (this[key] as? JsonPrimitive)?.takeIf { it.isString }?.content

fun JsonObject.long(key: String): Long? {
    val p = this[key] as? JsonPrimitive ?: return null
    if (p.isString) return null
    return p.content.toLongOrNull() ?: p.content.toDoubleOrNull()?.toLong()
}

fun JsonObject.int(key: String): Int? = long(key)?.toInt()

fun JsonObject.bool(key: String): Boolean? = (this[key] as? JsonPrimitive)?.takeIf { !it.isString }?.content?.let {
    when (it) {
        "true" -> true
        "false" -> false
        else -> null
    }
}

fun JsonObject.arr(key: String): JsonArray? = this[key] as? JsonArray

fun JsonObject.obj(key: String): JsonObject? = this[key] as? JsonObject

fun JsonObject.strList(key: String): List<String> =
    arr(key)?.mapNotNull { (it as? JsonPrimitive)?.takeIf { p -> p.isString }?.content } ?: emptyList()

/** Replace or add keys, keeping the order of the existing ones (like `{ ...obj, ...patch }`). A null value removes the key. */
fun JsonObject.with(patch: Map<String, JsonElement?>): JsonObject {
    val out = LinkedHashMap<String, JsonElement>(this)
    for ((key, v) in patch) if (v == null) out.remove(key) else out[key] = v
    return JsonObject(out)
}

fun JsonObject.with(vararg patch: Pair<String, JsonElement?>): JsonObject = with(patch.toMap())

fun jstr(s: String): JsonElement = JsonPrimitive(s)
fun jnum(n: Long): JsonElement = JsonPrimitive(n)
fun jnum(n: Int): JsonElement = JsonPrimitive(n)
fun jbool(b: Boolean): JsonElement = JsonPrimitive(b)
val jnull: JsonElement = JsonNull
fun jarr(items: Iterable<JsonElement>): JsonArray = JsonArray(items.toList())
fun jstrs(items: Iterable<String>): JsonArray = JsonArray(items.map { JsonPrimitive(it) })
