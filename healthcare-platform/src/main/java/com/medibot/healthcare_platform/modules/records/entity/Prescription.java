package com.medibot.healthcare_platform.modules.records.entity;

import jakarta.persistence.*;
import lombok.*;
import java.util.UUID;

@Entity
@Table(name = "prescriptions")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class Prescription {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "record_id", nullable = false)
    private MedicalRecord medicalRecord;

    @Column(nullable = false)
    private String medicineName;

    private String dosage; // e.g., "500mg"
    private String frequency; // e.g., "Twice a day"
    private String duration; // e.g., "5 days"
    private String instructions; // e.g., "Take after food"
}