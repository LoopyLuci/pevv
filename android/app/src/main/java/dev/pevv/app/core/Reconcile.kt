package dev.pevv.app.core

/** Where a remote copy of the vault came from: the cloud file (sync) or a live paired device. */
enum class RemoteSource { CLOUD, PEER }

/** What to do with a remote copy. [ADOPT] replaces the local file; [MERGE_ROSTER] only folds the device list in. */
enum class ReconcileAction { ADOPT, MERGE_ROSTER, IGNORE }

/**
 * The reconcile rules of `reconcileRemote` / `adoptRemote` in src/pevv/store.ts, as one pure function.
 *
 * - A vault this device was told to drop is never taken back.
 * - Only the same vault id is ever merged, and only a strictly higher revision replaces items (last writer wins on `rev`).
 * - A live paired device always counts; the cloud copy only when sync is on (or when there is no local vault at all).
 * - With no local vault, only the cloud copy installs one (a peer cannot).
 * - An unlocked vault always folds the device list in (union; a revoked device stays revoked), even when items are not taken.
 */
object Reconcile {
    fun decide(
        hasLocal: Boolean,
        localId: String,
        localRev: Long,
        remoteId: String,
        remoteRev: Long,
        unlocked: Boolean,
        source: RemoteSource,
        prefSync: Boolean,
        revokedLocally: Boolean,
    ): ReconcileAction {
        if (revokedLocally) return ReconcileAction.IGNORE
        if (hasLocal && localId != remoteId) return ReconcileAction.IGNORE
        val takeEntries = source == RemoteSource.PEER || !hasLocal || prefSync
        if (!hasLocal) return if (source == RemoteSource.CLOUD) ReconcileAction.ADOPT else ReconcileAction.IGNORE
        val higher = remoteRev > localRev
        if (!unlocked) return if (takeEntries && higher) ReconcileAction.ADOPT else ReconcileAction.IGNORE
        return if (takeEntries && higher) ReconcileAction.ADOPT else ReconcileAction.MERGE_ROSTER
    }
}
