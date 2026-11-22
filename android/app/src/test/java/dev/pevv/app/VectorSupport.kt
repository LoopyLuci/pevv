package dev.pevv.app

import dev.pevv.app.core.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import java.io.File

/** Loads the golden vectors that scripts/android-vectors.mjs wrote with the TypeScript code. */
object Vectors {
    val dir: File = File(System.getProperty("pevv.vectors") ?: error("pevv.vectors is not set"))

    fun load(name: String): JsonElement {
        val f = File(dir, "$name.json")
        check(f.exists()) { "missing vector file ${f.name}; run: node scripts/android-vectors.mjs" }
        return Json.parse(f.readText(Charsets.UTF_8))
    }

    fun obj(name: String) = load(name) as JsonObject
    fun arr(name: String) = load(name) as JsonArray
}

fun JsonElement.o() = this as JsonObject
fun JsonElement.a() = this as JsonArray
fun JsonElement.s() = (this as kotlinx.serialization.json.JsonPrimitive).content
fun JsonElement.l() = (this as kotlinx.serialization.json.JsonPrimitive).content.toLong()
fun JsonElement.b() = (this as kotlinx.serialization.json.JsonPrimitive).content.toBoolean()
