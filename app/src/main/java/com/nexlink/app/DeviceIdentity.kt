
package com.nexlink.app

import android.content.Context
import java.util.UUID

object DeviceIdentity {

    private const val PREFS_NAME = "nexlink_settings"
    private const val KEY_DEVICE_ID = "device_id"

    fun getOrCreateDeviceId(context: Context): String {

        val preferences = context.getSharedPreferences(
            PREFS_NAME,
            Context.MODE_PRIVATE
        )

        val savedId = preferences.getString(KEY_DEVICE_ID, null)?.takeIf { it.isNotBlank() }

        if (savedId != null) {
            return savedId
        }

        val newId = UUID.randomUUID().toString()

        preferences.edit()
            .putString(KEY_DEVICE_ID, newId)
            .apply()

        return newId
    }
}

