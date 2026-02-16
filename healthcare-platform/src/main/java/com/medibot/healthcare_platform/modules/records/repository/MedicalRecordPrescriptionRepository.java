
package com.medibot.healthcare_platform.modules.records.repository;

import com.medibot.healthcare_platform.modules.records.entity.Prescription;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.UUID;

@Repository
public interface MedicalRecordPrescriptionRepository extends JpaRepository<Prescription, UUID> {
    // This handles prescriptions inside the permanent Medical Records module
}