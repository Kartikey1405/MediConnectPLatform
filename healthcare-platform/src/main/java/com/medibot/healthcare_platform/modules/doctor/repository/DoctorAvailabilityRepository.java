package com.medibot.healthcare_platform.modules.doctor.repository;

import com.medibot.healthcare_platform.modules.doctor.entity.DoctorAvailability;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.time.LocalDate;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface DoctorAvailabilityRepository extends JpaRepository<DoctorAvailability, UUID> {
    List<DoctorAvailability> findByDoctorIdAndDateBetween(UUID doctorId, LocalDate from, LocalDate to);
    Optional<DoctorAvailability> findByDoctorIdAndDate(UUID doctorId, LocalDate date);
}