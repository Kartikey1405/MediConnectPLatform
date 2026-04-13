package com.medibot.healthcare_platform.modules.reportinsight.entity;

import com.medibot.healthcare_platform.modules.identity.entity.User;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "report_insights")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class ReportInsight {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "patient_id", nullable = false)
    private User patient;

    @Column(nullable = false)
    private String imageUrl;

    @Column(columnDefinition = "TEXT")
    private String findings;

    @Column(columnDefinition = "TEXT")
    private String possibleCondition;

    @Column(columnDefinition = "TEXT")
    private String recommendations;

    // e.g. "LOW", "MODERATE", "HIGH"
    private String riskLevel;

    @CreationTimestamp
    private LocalDateTime createdAt;
}