package com.medibot.healthcare_platform.modules.consultation.repository;

import com.medibot.healthcare_platform.modules.consultation.entity.Consultation;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface ConsultationRepository extends JpaRepository<Consultation, UUID> {

    // Finds the live session linked to a specific booking
    Optional<Consultation> findByBookingId(UUID bookingId);

    // Fetches history for the Patient Dashboard
    List<Consultation> findByBookingPatientIdAndIsCompletedTrueOrderByCreatedAtDesc(UUID patientId);
}