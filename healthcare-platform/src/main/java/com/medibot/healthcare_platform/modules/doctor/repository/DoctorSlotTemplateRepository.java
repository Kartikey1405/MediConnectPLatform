package com.medibot.healthcare_platform.modules.doctor.repository;

import com.medibot.healthcare_platform.modules.doctor.entity.DoctorSlotTemplate;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.List;
import java.util.UUID;

@Repository
public interface DoctorSlotTemplateRepository extends JpaRepository<DoctorSlotTemplate, UUID> {
    List<DoctorSlotTemplate> findByDoctorId(UUID doctorId);
    void deleteByDoctorId(UUID doctorId);
}