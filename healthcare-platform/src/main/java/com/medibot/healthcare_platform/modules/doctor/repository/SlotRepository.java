package com.medibot.healthcare_platform.modules.doctor.repository;

import com.medibot.healthcare_platform.modules.doctor.entity.Slot;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

@Repository
public interface SlotRepository extends JpaRepository<Slot, UUID> {

    /**
     * Finds all available slots for a specific doctor that haven't started yet.
     * This handles the "No Expired Slots" edge case.
     */
    @Query("SELECT s FROM Slot s WHERE s.doctor.id = :doctorId " +
            "AND s.status = 'AVAILABLE' " +
            "AND s.startTime > :now " +
            "ORDER BY s.startTime ASC")
    List<Slot> findAvailableSlots(@Param("doctorId") UUID doctorId,
                                  @Param("now") LocalDateTime now);

    /**
     * Finds slots that have been "LOCKED" for too long.
     * Used by a background task to release slots if payment fails.
     */
    @Query("SELECT s FROM Slot s WHERE s.status = 'LOCKED' " +
            "AND s.lockedAt < :expiryTime")
    List<Slot> findExpiredLocks(@Param("expiryTime") LocalDateTime expiryTime);
}