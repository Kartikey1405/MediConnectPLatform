
//@Entity
//@Table(name = "departments")
//@Getter @Setter
//@NoArgsConstructor @AllArgsConstructor
//@Builder
//public class Department {
//
//    @Id
//    @GeneratedValue(strategy = GenerationType.AUTO)
//    private UUID id;
//
//    @Column(nullable = false)
//    private String name; // e.g., "Department of Cardiology"
//
//    private String specialty; // e.g., "Cardiology" - Used for filtering doctors
//
//    private Double consultationFee; // Essential for the Razorpay/Video Call logic
//
//    @ManyToOne(fetch = FetchType.LAZY)
//    @JoinColumn(name = "hospital_id", nullable = false)
//    private Hospital hospital;
//}



package com.medibot.healthcare_platform.modules.hospital.entity;

import com.fasterxml.jackson.annotation.JsonBackReference;
import jakarta.persistence.*;
import lombok.*;
import java.util.UUID;

@Entity
@Table(name = "departments")
@Getter @Setter
@NoArgsConstructor @AllArgsConstructor
@Builder
public class Department {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private UUID id;

    @Column(nullable = false)
    private String name;

    private String specialty;

    private Double consultationFee;

    // FIX: BackReference stops the serializer from looping back to Hospital
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "hospital_id", nullable = false)
    @JsonBackReference
    private Hospital hospital;
}