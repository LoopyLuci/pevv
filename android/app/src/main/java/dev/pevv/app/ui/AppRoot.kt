package dev.pevv.app.ui

import androidx.activity.compose.BackHandler
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import dev.pevv.app.pevv
import dev.pevv.app.store.VaultController.Status

sealed interface Route {
    data object List : Route
    data class Detail(val id: String) : Route
    data class Edit(val id: String?, val type: String) : Route
    data object Generator : Route
    data object Settings : Route
    data class Sub(val which: SettingsRoute) : Route
    data object Share : Route
    data object Scan : Route
}

/** What the activity shows for the current vault state. Navigation inside the unlocked vault is a plain back stack. */
@Composable
fun AppRoot() {
    val ctl = LocalContext.current.pevv.vault
    when (ctl.status) {
        Status.NONE -> {
            var scanning by remember { mutableStateOf(false) }
            if (scanning) { BackHandler { scanning = false }; ScanScreen { scanning = false } } else OnboardingScreen(onScan = { scanning = true })
        }
        Status.LOCKED -> UnlockScreen()
        Status.SECOND_FACTOR -> SecondFactorScreen()
        Status.SET_PASSWORD -> SetPasswordScreen()
        Status.UNLOCKED -> UnlockedHost()
    }
}

@Composable
private fun UnlockedHost() {
    val stack = remember { mutableStateListOf<Route>(Route.List) }
    val top = stack.last()
    fun push(r: Route) = stack.add(r)
    fun pop() { if (stack.size > 1) stack.removeAt(stack.lastIndex) }
    BackHandler(enabled = stack.size > 1) { pop() }
    when (top) {
        Route.List -> ItemListScreen(onOpen = { push(Route.Detail(it)) }, onNew = { push(Route.Edit(null, it)) }, onSettings = { push(Route.Settings) }, onGenerator = { push(Route.Generator) })
        is Route.Detail -> ItemDetailScreen(top.id, onBack = ::pop, onEdit = { push(Route.Edit(top.id, "")) })
        is Route.Edit -> ItemEditScreen(top.id, top.type, onDone = { id -> pop(); if (top.id == null && id != null) push(Route.Detail(id)) }, onBack = ::pop)
        Route.Generator -> GeneratorScreen(::pop)
        Route.Settings -> SettingsScreen(::pop, onShare = { push(Route.Share) }, onRoute = { push(Route.Sub(it)) })
        is Route.Sub -> when (top.which) {
            SettingsRoute.DEVICES -> DevicesScreen(::pop)
            SettingsRoute.RECOVERY -> RecoveryScreen(::pop)
            SettingsRoute.IMPORT -> ImportScreen(::pop)
            SettingsRoute.FACTORS -> FactorsScreen(::pop)
            SettingsRoute.SYNC -> SyncScreen(::pop)
            SettingsRoute.UPDATES -> UpdatesScreen(::pop)
            SettingsRoute.MAIN -> SettingsScreen(::pop, onShare = { push(Route.Share) }, onRoute = { push(Route.Sub(it)) })
        }
        Route.Share -> ShareVaultScreen(::pop)
        Route.Scan -> ScanScreen(::pop)
    }
}
