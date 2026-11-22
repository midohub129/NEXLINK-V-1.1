package com.nexlink.app.data.local

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase

@Database(
    entities = [
        SyncEvent::class
    ],
    version = 1,
    exportSchema = false
)
abstract class NexlinkDatabase : RoomDatabase() {

    abstract fun syncEventDao(): SyncEventDao

    companion object {

        @Volatile
        private var INSTANCE: NexlinkDatabase? = null

        fun getInstance(context: Context): NexlinkDatabase {
            return INSTANCE ?: synchronized(this) {
                INSTANCE ?: Room.databaseBuilder(
                    context.applicationContext,
                    NexlinkDatabase::class.java,
                    "nexlink_database"
                ).build().also {
                    INSTANCE = it
                }
            }
        }
    }
}
