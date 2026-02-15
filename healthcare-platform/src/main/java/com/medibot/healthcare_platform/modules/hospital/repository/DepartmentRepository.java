

package com.medibot.healthcare_platform.modules.hospital.repository;

import com.medibot.healthcare_platform.modules.hospital.entity.Department;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;
import java.util.UUID;

public interface DepartmentRepository extends JpaRepository<Department, UUID> {
    List<Department> findByHospitalId(UUID hospitalId);
}