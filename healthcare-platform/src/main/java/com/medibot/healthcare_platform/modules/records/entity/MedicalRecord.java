////package com.medibot.healthcare_platform.modules.records.entity;
////
////import com.medibot.healthcare_platform.modules.identity.entity.User;
////import com.medibot.healthcare_platform.modules.doctor.entity.Doctor;
////import jakarta.persistence.*;
////import lombok.*;
////import org.hibernate.annotations.CreationTimestamp;
////import java.time.LocalDateTime;
////import java.util.List;
////import java.util.UUID;
////
////@Entity
////@Table(name = "medical_records")
////@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
////public class MedicalRecord {
////    @Id
////    @GeneratedValue(strategy = GenerationType.AUTO)
////    private UUID id;
////
////    @ManyToOne(fetch = FetchType.LAZY)
////    @JoinColumn(name = "patient_id", nullable = false)
////    private User patient;
////
////    // Doctor is nullable because a patient might upload their own report (e.g. Blood Test)
////    @ManyToOne(fetch = FetchType.LAZY)
////    @JoinColumn(name = "doctor_id")
////    private Doctor doctor;
////
////    private String title; // e.g., "Blood Test Report", "X-Ray Jan 2026"
////
////    @Column(columnDefinition = "TEXT")
////    private String diagnosis;
////
////    @Column(columnDefinition = "TEXT")
////    private String symptoms;
////
////    // CLOUDINARY FIELDS
////    private String fileUrl;  // The URL returned by Cloudinary
////    private String fileType; // pdf, image, etc.
////
////    @OneToMany(mappedBy = "medicalRecord", cascade = CascadeType.ALL)
////    private List<Prescription> prescriptions;
////
////    @CreationTimestamp
////    private LocalDateTime createdAt;
////}
//
//package com.medibot.healthcare_platform.modules.records.entity;
//
//import com.medibot.healthcare_platform.modules.identity.entity.User;
//import com.medibot.healthcare_platform.modules.doctor.entity.Doctor;
//import jakarta.persistence.*;
//import lombok.*;
//import org.hibernate.annotations.CreationTimestamp;
//import java.time.LocalDateTime;
//import java.util.List;
//import java.util.UUID;
//
//@Entity
//@Table(name = "medical_records")
//@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
//public class MedicalRecord {
//    @Id
//    @GeneratedValue(strategy = GenerationType.AUTO)
//    private UUID id;
//
//    @ManyToOne(fetch = FetchType.LAZY)
//    @JoinColumn(name = "patient_id", nullable = false)
//    private User patient;
//
//    // Doctor is nullable because a patient might upload their own report (e.g. Blood Test)
//    @ManyToOne(fetch = FetchType.LAZY)
//    @JoinColumn(name = "doctor_id")
//    private Doctor doctor;
//
//    private String title; // e.g., "Blood Test Report", "X-Ray Jan 2026"
//
//    @Column(columnDefinition = "TEXT")
//    private String diagnosis;
//
//    @Column(columnDefinition = "TEXT")
//    private String symptoms;
//
//    // CLOUDINARY FIELDS
//    private String fileUrl;  // The URL returned by Cloudinary
//    private String fileType; // pdf, image, etc.
//
//    @OneToMany(mappedBy = "medicalRecord", cascade = CascadeType.ALL)
//    private List<Prescription> prescriptions;
//
//    @CreationTimestamp
//    private LocalDateTime createdAt;
//}


package com.medibot.healthcare_platform.modules.records.entity;

import com.medibot.healthcare_platform.modules.identity.entity.User;
import com.medibot.healthcare_platform.modules.doctor.entity.Doctor;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

@Entity
@Table(name = "medical_records")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class MedicalRecord {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "patient_id", nullable = false)
    private User patient;

    // FIX: Explicitly allow nullable=true so patients can upload self-reports
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "doctor_id", nullable = true)
    private Doctor doctor;

    private String title;

    @Column(columnDefinition = "TEXT")
    private String diagnosis;

    @Column(columnDefinition = "TEXT")
    private String symptoms;

    private String fileUrl;
    private String fileType;

    @OneToMany(mappedBy = "medicalRecord", cascade = CascadeType.ALL)
    private List<Prescription> prescriptions;

    @CreationTimestamp
    private LocalDateTime createdAt;
}