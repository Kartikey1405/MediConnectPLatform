package com.medibot.healthcare_platform.modules.records.repository;

import com.medibot.healthcare_platform.modules.records.entity.MedicalRecord;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;
import java.util.UUID;

public interface MedicalRecordRepository extends JpaRepository<MedicalRecord, UUID> {
    List<MedicalRecord> findByPatientIdOrderByCreatedAtDesc(UUID patientId);
    List<MedicalRecord> findByDoctorIdOrderByCreatedAtDesc(UUID doctorId);
}