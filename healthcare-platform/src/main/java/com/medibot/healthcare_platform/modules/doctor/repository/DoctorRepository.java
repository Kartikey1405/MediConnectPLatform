package com.medibot.healthcare_platform.modules.doctor.repository;

import com.medibot.healthcare_platform.modules.doctor.entity.Doctor;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface DoctorRepository extends JpaRepository<Doctor, UUID> {

    // Find verified doctors in a specific department (Mapping AI prediction to Doctors)
    List<Doctor> findByDepartmentIdAndIsVerifiedTrue(UUID departmentId);

    // Find all doctors in a hospital
    List<Doctor> findByHospitalId(UUID hospitalId);
}