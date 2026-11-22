package com.nexlink.app

import android.app.Notification
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import android.util.Log
import com.nexlink.app.data.local.NexlinkDatabase
import com.nexlink.app.data.local.SyncEvent
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import org.json.JSONObject

class NotificationCaptureService : NotificationListenerService() {

    companion object {
        private const val TAG = "NEXLINK_NOTIFICATIONS"
        private const val PREFS_NAME = "nexlink_settings"
        private const val KEY_SELECTED_APPS = "selected_notification_apps"
    }

    private val serviceScope = CoroutineScope(
        SupervisorJob() + Dispatchers.IO
    )

    override fun onListenerConnected() {
        super.onListenerConnected()
        Log.i(TAG, "Notification access connected")
    }

    override fun onListenerDisconnected() {
        super.onListenerDisconnected()
        Log.i(TAG, "Notification access disconnected")
    }

    override fun onNotificationPosted(
        sbn: StatusBarNotification
    ) {
        super.onNotificationPosted(sbn)
        Log.i(TAG, "DEBUG package=${sbn.packageName}, key=${sbn.key}, id=${sbn.id}, tag=${sbn.tag}, postTime=${sbn.postTime}")

        if (sbn.packageName == packageName) {
            return
        }

        val preferences = getSharedPreferences(
            PREFS_NAME,
            MODE_PRIVATE
        )

        val selectedApps = preferences.getStringSet(
            KEY_SELECTED_APPS,
            emptySet()
        ) ?: emptySet()

        if (sbn.packageName !in selectedApps) {
            return
        }

        val extras = sbn.notification.extras

        val title = extras
            .getCharSequence(Notification.EXTRA_TITLE)
            ?.toString()
            ?: ""

        val text = extras
            .getCharSequence(Notification.EXTRA_TEXT)
            ?.toString()
            ?: ""

        val payload = JSONObject().apply {
            put("packageName", sbn.packageName)
            put("title", title)
            put("text", text)
            put("postedAt", sbn.postTime)
        }.toString()

        serviceScope.launch {
            try {
                val database = NexlinkDatabase.getInstance(this@NotificationCaptureService)

                database.syncEventDao().insert(
                    SyncEvent(
                        type = "notification",
                        payload = payload
                    )
                )

                Log.i(TAG, "Notification saved to sync queue")
            } catch (error: Exception) {
                Log.e(TAG, "Failed to save notification", error)
            }
        }
    }
}
