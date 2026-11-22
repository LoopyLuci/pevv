package dev.pevv.app.core

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

data class VaultDevice(val id: String, val name: String, val kind: String, val added: Long, val seen: Long, val agent: String) {
    fun toJson(): JsonObject = buildJsonObject {
        put("id", id); put("name", name); put("kind", kind); put("added", added); put("seen", seen); put("agent", agent)
    }
}

data class RosterSlice(val devices: List<VaultDevice>, val revokedDevices: List<String>)

/** The device roster inside the sealed meta. A port of the pure parts of src/pevv/devices.ts. */
object Devices {
    const val DEVICE_CAP = 40
    const val SEEN_WINDOW_MS = 60L * 60 * 1000
    private val ID = Regex("^[0-9a-f-]{8,64}$", RegexOption.IGNORE_CASE)
    private val CONTROL = Regex("[\\u0000-\\u001f]")

    fun cleanDeviceName(name: String): String = name.replace(CONTROL, "").trim().take(40)

    fun validDeviceId(id: String) = ID.matches(id)

    fun asDevices(v: JsonElement?): List<VaultDevice> {
        val arr = v as? JsonArray ?: return emptyList()
        val out = ArrayList<VaultDevice>()
        for (d in arr) {
            val r = d as? JsonObject ?: continue
            val id = r.str("id") ?: continue
            if (!ID.matches(id)) continue
            val name = r.str("name") ?: continue
            val kind = r.str("kind")?.takeIf { it in setOf("phone", "tablet", "desktop", "unknown") } ?: "unknown"
            out.add(VaultDevice(id, cleanDeviceName(name).ifEmpty { "Device" }, kind, r.long("added") ?: 0, r.long("seen") ?: 0, (r.str("agent") ?: "").take(80)))
        }
        return out
    }

    /** Union by id. A newer `seen` wins that device's name; `added` stays the earliest. */
    fun mergeDevices(a: List<VaultDevice>, b: List<VaultDevice>): List<VaultDevice> {
        val map = LinkedHashMap<String, VaultDevice>()
        for (d in a + b) {
            val cur = map[d.id]
            if (cur == null) {
                map[d.id] = d
                continue
            }
            val newer = if (d.seen >= cur.seen) d else cur
            val older = if (newer === d) cur else d
            val added = if (older.added != 0L && newer.added != 0L) minOf(older.added, newer.added) else if (older.added != 0L) older.added else newer.added
            map[d.id] = newer.copy(added = added)
        }
        return map.values.sortedByDescending { it.seen }.take(DEVICE_CAP)
    }

    /** Union of two rosters. A removed device stays removed even when the other copy still lists it. */
    fun mergeRoster(a: RosterSlice, b: RosterSlice): RosterSlice {
        val revoked = (a.revokedDevices + b.revokedDevices).distinct().filter { ID.matches(it) }.take(100)
        val devices = mergeDevices(a.devices, b.devices).filter { it.id !in revoked }
        return RosterSlice(devices, revoked)
    }

    fun sameRoster(a: RosterSlice, b: RosterSlice): Boolean {
        if (a.revokedDevices.size != b.revokedDevices.size || a.devices.size != b.devices.size) return false
        val revoked = b.revokedDevices.toSet()
        if (a.revokedDevices.any { it !in revoked }) return false
        val map = b.devices.associateBy { it.id }
        return a.devices.all { d ->
            val o = map[d.id]
            o != null && o.name == d.name && o.kind == d.kind && o.agent == d.agent && o.seen == d.seen && o.added == d.added
        }
    }

    fun deviceNeedsWrite(prev: VaultDevice?, next: VaultDevice, now: Long = next.seen): Boolean {
        if (prev == null) return true
        if (prev.name != next.name || prev.kind != next.kind || prev.agent != next.agent) return true
        return now - prev.seen > SEEN_WINDOW_MS
    }

    fun devicesJson(list: List<VaultDevice>): JsonArray = JsonArray(list.map { it.toJson() })
}
