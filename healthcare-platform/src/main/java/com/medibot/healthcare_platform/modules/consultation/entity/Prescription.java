package com.medibot.healthcare_platform.modules.consultation.entity;

import jakarta.persistence.*;
import lombok.*;
import java.util.UUID;

@Entity(name = "ConsultationPrescription") // Add this name attribute
@Table(name = "consultation_prescriptions")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class Prescription {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "consultation_id")
    private Consultation consultation;

    private String medicineName;
    private String dosage;    // e.g., "500mg"
    private String frequency; // e.g., "Twice a day"
    private String duration;  // e.g., "5 days"
    private String instructions; // e.g., "After food"
}