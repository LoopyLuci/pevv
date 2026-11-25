package dev.pevv.app.update

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInstaller
import android.os.Build
import androidx.work.BackoffPolicy
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.ExistingWorkPolicy
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import dev.pevv.app.pevv
import java.util.concurrent.TimeUnit

/** About every 12 hours: ask GitHub for a newer release. */
class UpdateCheckWorker(ctx: Context, params: WorkerParameters) : CoroutineWorker(ctx, params) {
    override suspend fun doWork(): Result {
        applicationContext.pevv.updates.backgroundCheck()
        return Result.success()
    }
}

/** Downloads and verifies the APK in the background (automatic modes), then notifies or installs. */
class UpdateDownloadWorker(ctx: Context, params: WorkerParameters) : CoroutineWorker(ctx, params) {
    override suspend fun doWork(): Result {
        applicationContext.pevv.updates.backgroundDownload()
        return Result.success()
    }
}

object UpdateScheduler {
    private const val PERIODIC = "pevv-update-check"
    private const val DOWNLOAD = "pevv-update-download"

    fun schedulePeriodic(ctx: Context) {
        val c = Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).setRequiresBatteryNotLow(true).build()
        val req = PeriodicWorkRequestBuilder<UpdateCheckWorker>(12, TimeUnit.HOURS).setConstraints(c)
            .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 30, TimeUnit.MINUTES).build()
        WorkManager.getInstance(ctx).enqueueUniquePeriodicWork(PERIODIC, ExistingPeriodicWorkPolicy.UPDATE, req)
    }

    /** Unmetered only (the default) and battery not low; one download at a time. */
    fun enqueueDownload(ctx: Context, prefs: UpdatePrefs) {
        val c = Constraints.Builder()
            .setRequiredNetworkType(if (prefs.unmeteredOnly) NetworkType.UNMETERED else NetworkType.CONNECTED)
            .setRequiresBatteryNotLow(true).setRequiresStorageNotLow(true).build()
        val req = OneTimeWorkRequestBuilder<UpdateDownloadWorker>().setConstraints(c)
            .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 30, TimeUnit.MINUTES).build()
        WorkManager.getInstance(ctx).enqueueUniqueWork(DOWNLOAD, ExistingWorkPolicy.KEEP, req)
    }
}

/** Receives the PackageInstaller session result (not exported; only our own PendingIntent reaches it). */
class UpdateInstallReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != ACTION) return
        val status = intent.getIntExtra(PackageInstaller.EXTRA_STATUS, PackageInstaller.STATUS_FAILURE)
        val confirm: Intent? = if (Build.VERSION.SDK_INT >= 33) intent.getParcelableExtra(Intent.EXTRA_INTENT, Intent::class.java)
        else @Suppress("DEPRECATION") intent.getParcelableExtra(Intent.EXTRA_INTENT)
        context.pevv.updates.onInstallStatus(status, confirm, intent.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE))
    }

    companion object { const val ACTION = "dev.pevv.app.update.INSTALL_RESULT" }
}
