package com.medibot.healthcare_platform.modules.doctor.entity;

import jakarta.persistence.*;
import lombok.*;
import java.time.LocalTime;
import java.util.UUID;

@Entity
@Table(name = "doctor_slot_templates")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class DoctorSlotTemplate {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "doctor_id", nullable = false)
    private Doctor doctor;

    // e.g. "Morning Session", "Afternoon Session", "Evening Session"
    private String label;

    // e.g. 09:30
    @Column(nullable = false)
    private LocalTime startTime;

    // e.g. 11:00
    @Column(nullable = false)
    private LocalTime endTime;
}