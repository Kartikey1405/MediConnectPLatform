////package com.medibot.healthcare_platform.modules.hospital.entity;
////
////import jakarta.persistence.*;
////        import lombok.*;
////        import org.hibernate.annotations.CreationTimestamp;
////import java.time.LocalDateTime;
////import java.util.List;
////import java.util.UUID;
////
////@Entity
////@Table(name = "hospitals")
////@Getter @Setter
////@NoArgsConstructor @AllArgsConstructor
////@Builder
////public class Hospital {
////
////    @Id
////    @GeneratedValue(strategy = GenerationType.AUTO)
////    private UUID id;
////
////    @Column(nullable = false)
////    private String name;
////
////    @Column(nullable = false, columnDefinition = "TEXT")
////    private String address;
////
////    // For "Nearest Hospital" logic
////    private Double latitude;
////    private Double longitude;
////
////    private String contactNumber;
////
////    @OneToMany(mappedBy = "hospital", cascade = CascadeType.ALL)
////    private List<Department> departments;
////
////    @CreationTimestamp
////    private LocalDateTime createdAt;
////
////    private boolean isActive = true;
////}
//

//
//@Entity
//@Table(name = "hospitals")
//@Getter @Setter
//@NoArgsConstructor @AllArgsConstructor
//@Builder
//public class Hospital {
//
//    @Id
//    @GeneratedValue(strategy = GenerationType.AUTO)
//    private UUID id;
//
//    @Column(nullable = false)
//    private String name;
//
//    @Column(nullable = false, columnDefinition = "TEXT")
//    private String address;
//
//    // Fixed: Coordinates are now mandatory for the SOS Haversine logic
//    @Column(nullable = false)
//    private Double latitude;
//
//    @Column(nullable = false)
//    private Double longitude;
//
//    private String contactNumber;
//
//    // Explicitly using LAZY fetch for performance
//    @OneToMany(mappedBy = "hospital", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
//    private List<Department> departments;
//
//    @CreationTimestamp
//    @Column(updatable = false)
//    private LocalDateTime createdAt;
//
//    // Fixed: Builder.Default ensures 'true' is set when using Hospital.builder()
//    @Builder.Default
//    private boolean isActive = true;
//}



package com.medibot.healthcare_platform.modules.hospital.entity;

import com.fasterxml.jackson.annotation.JsonManagedReference;
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

    @Column(nullable = false)
    private Double latitude;

    @Column(nullable = false)
    private Double longitude;

    private String contactNumber;

    // FIX: Add ManagedReference to break the loop
    @OneToMany(mappedBy = "hospital", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    @JsonManagedReference
    private List<Department> departments;

    @CreationTimestamp
    @Column(updatable = false)
    private LocalDateTime createdAt;

    @Builder.Default
    private boolean isActive = true;
}