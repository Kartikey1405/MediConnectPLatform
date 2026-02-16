
//@Entity
//@Table(name = "doctors")
//@Getter @Setter
//@NoArgsConstructor @AllArgsConstructor
//@Builder
//public class Doctor {
//
//    @Id
//    @GeneratedValue(strategy = GenerationType.AUTO)
//    private UUID id;
//
//    // Link to the Core User (for login/email)
//    @OneToOne(cascade = CascadeType.ALL)
//    @JoinColumn(name = "user_id", referencedColumnName = "id")
//    private User user;
//
//    @ManyToOne
//    @JoinColumn(name = "hospital_id")
//    private Hospital hospital;
//
//    @ManyToOne
//    @JoinColumn(name = "department_id")
//    private Department department;
//
//    private String specialization;
//
//    @Column(nullable = false)
//    private Double consultationFee;
//
//    @Column(columnDefinition = "TEXT")
//    private String bio;
//
//    private boolean isVerified = false; // Set to true by ADMIN
//}



package com.medibot.healthcare_platform.modules.doctor.entity;

import com.medibot.healthcare_platform.modules.identity.entity.User;
import com.medibot.healthcare_platform.modules.hospital.entity.Hospital;
import com.medibot.healthcare_platform.modules.hospital.entity.Department;
import jakarta.persistence.*;
import lombok.*;
import java.util.UUID;

@Entity
@Table(name = "doctors")
@Getter @Setter
@NoArgsConstructor @AllArgsConstructor
@Builder
public class Doctor {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private UUID id;

    // FIX: Ensure the join column exactly matches your database schema
    @OneToOne(cascade = CascadeType.ALL)
    @JoinColumn(name = "user_id", referencedColumnName = "id")
    private User user;

    @ManyToOne
    @JoinColumn(name = "hospital_id")
    private Hospital hospital;

    @ManyToOne
    @JoinColumn(name = "department_id")
    private Department department;

    private String specialization;

    @Column(nullable = false)
    private Double consultationFee;

    @Column(columnDefinition = "TEXT")
    private String bio;

    // Standardizing name for frontend boolean checks
    private boolean isVerified = false;
}