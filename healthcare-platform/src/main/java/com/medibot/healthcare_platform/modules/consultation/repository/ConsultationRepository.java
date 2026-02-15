package com.medibot.healthcare_platform.modules.consultation.repository;

import com.medibot.healthcare_platform.modules.consultation.entity.Consultation;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface ConsultationRepository extends JpaRepository<Consultation, UUID> {

    /**
     * Find a consultation by its associated booking ID.
     * Useful for checking if a session has already started for a specific appointment.
     */
    Optional<Consultation> findByBookingId(UUID bookingId);

    /**
     * Check if a consultation is already completed for a booking.
     */
    boolean existsByBookingIdAndIsCompletedTrue(UUID bookingId);
}