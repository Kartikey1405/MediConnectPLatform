//package com.medibot.healthcare_platform.modules.consultation.repository;
//
//import com.medibot.healthcare_platform.modules.consultation.entity.Prescription;
//import org.springframework.data.jpa.repository.JpaRepository;
//import org.springframework.stereotype.Repository;
//
//import java.util.List;
//import java.util.UUID;
//
//@Repository
//public interface ConsultationPrescriptionRepository extends JpaRepository<Prescription, UUID> {
//    // Finds all medicines linked to a specific consultation for the patient's history
//    List<Prescription> findByConsultationId(UUID consultationId);
//}


package com.medibot.healthcare_platform.modules.consultation.repository;

import com.medibot.healthcare_platform.modules.consultation.entity.Prescription;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.List;
import java.util.UUID;

@Repository
public interface ConsultationPrescriptionRepository extends JpaRepository<Prescription, UUID> {
    List<Prescription> findByConsultationId(UUID consultationId);
}