package com.medibot.healthcare_platform.modules.triage.entity;

import com.medibot.healthcare_platform.modules.identity.entity.User;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "triage_history")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class TriageHistory {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "patient_id", nullable = false)
    private User patient;

    private String predictedDisease;
    private double confidence;

    @Column(columnDefinition = "TEXT")
    private String symptomsInput; // What the user typed in chat

    @Column(columnDefinition = "TEXT")
    private String aiAdvice; // The formatted Gemini advice (Tips + Alert)

    @CreationTimestamp
    private LocalDateTime createdAt;
}