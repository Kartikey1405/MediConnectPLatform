package com.medibot.healthcare_platform.modules.hospital.repository;

import com.medibot.healthcare_platform.modules.hospital.entity.Hospital;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.UUID;

public interface HospitalRepository extends JpaRepository<Hospital, UUID> {
    // You can add custom queries here later, like finding by name
}