package com.medibot.healthcare_platform.modules.reportinsight.repository;

import com.medibot.healthcare_platform.modules.reportinsight.entity.ReportInsight;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface ReportInsightRepository extends JpaRepository<ReportInsight, UUID> {
    List<ReportInsight> findByPatientIdOrderByCreatedAtDesc(UUID patientId);
}