package com.nexlink.app.data.local

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import kotlinx.coroutines.flow.Flow

@Dao
interface SyncEventDao {

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(event: SyncEvent): Long

    @Query(
        """
        SELECT * FROM sync_events
        WHERE status = 'PENDING'
        ORDER BY createdAt ASC
        """
    )
    suspend fun getPendingEvents(): List<SyncEvent>

    @Query("SELECT * FROM sync_events ORDER BY createdAt DESC")
    fun observeAllEvents(): Flow<List<SyncEvent>>


    @Query(
        """
        SELECT * FROM sync_events
        WHERE type = 'notification'
        ORDER BY createdAt DESC
        """
   )
    fun observeNotifications(): Flow<List<SyncEvent>>
    @Query(
        """
        UPDATE sync_events
        SET status = :status
        WHERE id = :eventId
        """
    )
    suspend fun updateStatus(
        eventId: Long,
        status: String
    )

    @Query(
        """
        UPDATE sync_events
        SET retryCount = retryCount + 1
        WHERE id = :eventId
        """
    )
    suspend fun incrementRetryCount(eventId: Long)

    @Query("DELETE FROM sync_events WHERE id = :eventId")
    suspend fun delete(eventId: Long)

    @Query("SELECT COUNT(*) FROM sync_events")
    suspend fun getEventCount(): Int
}
