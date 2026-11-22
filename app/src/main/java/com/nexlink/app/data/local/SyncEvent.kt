package com.nexlink.app.data.local

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "sync_events")
data class SyncEvent(

    @PrimaryKey(autoGenerate = true)
    val id: Long = 0,

    val type: String,

    val payload: String,

    val createdAt: Long = System.currentTimeMillis(),

    val status: String = "PENDING",

    val retryCount: Int = 0
)
