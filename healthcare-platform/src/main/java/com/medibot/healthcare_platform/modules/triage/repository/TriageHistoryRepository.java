package com.medibot.healthcare_platform.modules.triage.repository;



import com.medibot.healthcare_platform.modules.triage.entity.TriageHistory;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;
import java.util.UUID;

public interface TriageHistoryRepository extends JpaRepository<TriageHistory, UUID> {
    List<TriageHistory> findByPatientIdOrderByCreatedAtDesc(UUID patientId);
}
