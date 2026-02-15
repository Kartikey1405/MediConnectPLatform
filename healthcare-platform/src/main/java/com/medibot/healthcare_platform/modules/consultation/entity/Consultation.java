package com.medibot.healthcare_platform.modules.consultation.entity;

import com.medibot.healthcare_platform.modules.booking.entity.Booking;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "consultations")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class Consultation {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private UUID id;

    @OneToOne
    @JoinColumn(name = "booking_id", nullable = false)
    private Booking booking;

    @Column(columnDefinition = "TEXT")
    private String doctorNotes;

    private LocalDateTime startTime;
    private LocalDateTime endTime;

    private boolean isCompleted = false;

    @CreationTimestamp
    private LocalDateTime createdAt;
}