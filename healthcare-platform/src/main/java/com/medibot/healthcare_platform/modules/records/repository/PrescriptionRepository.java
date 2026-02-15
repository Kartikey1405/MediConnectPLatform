package com.medibot.healthcare_platform.modules.records.repository;

import com.medibot.healthcare_platform.modules.records.entity.Prescription;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.UUID;

public interface PrescriptionRepository extends JpaRepository<Prescription, UUID> {
    // Basic CRUD is sufficient as prescriptions are typically fetched via the MedicalRecord
}