package com.medibot.healthcare_platform.modules.hospital.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

@Entity
@Table(name = "hospitals")
@Getter @Setter
@NoArgsConstructor @AllArgsConstructor
@Builder
public class Hospital {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private UUID id;

    @Column(nullable = false)
    private String name;

    @Column(nullable = false, columnDefinition = "TEXT")
    private String address;

    // For "Nearest Hospital" logic
    private Double latitude;
    private Double longitude;

    private String contactNumber;

    @OneToMany(mappedBy = "hospital", cascade = CascadeType.ALL)
    private List<Department> departments;

    @CreationTimestamp
    private LocalDateTime createdAt;

    private boolean isActive = true;
}