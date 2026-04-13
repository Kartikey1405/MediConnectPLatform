package com.medibot.healthcare_platform.modules.doctor.entity;

import jakarta.persistence.*;
import lombok.*;
import java.time.LocalDate;
import java.util.UUID;

@Entity
@Table(name = "doctor_availability",
        uniqueConstraints = @UniqueConstraint(columnNames = {"doctor_id", "date"}))
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class DoctorAvailability {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "doctor_id", nullable = false)
    private Doctor doctor;

    @Column(nullable = false)
    private LocalDate date;

    // true = doctor is working that day, false = day off
    @Column(nullable = false)
    private boolean available = true;
}