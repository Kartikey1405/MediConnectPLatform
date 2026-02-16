//package com.medibot.healthcare_platform.modules.doctor.entity;
//
//import jakarta.persistence.*;
//import lombok.*;
//import java.time.LocalDateTime;
//import java.util.UUID;
//
//@Entity
//@Table(name = "availability_slots")
//@Getter @Setter
//@NoArgsConstructor @AllArgsConstructor
//@Builder
//public class Slot {
//
//    @Id
//    @GeneratedValue(strategy = GenerationType.AUTO)
//    private UUID id;
//
//    @ManyToOne(fetch = FetchType.LAZY)
//    @JoinColumn(name = "doctor_id", nullable = false)
//    private Doctor doctor;
//
//    @Column(nullable = false)
//    private LocalDateTime startTime;
//
//    @Column(nullable = false)
//    private LocalDateTime endTime;
//
//    @Enumerated(EnumType.STRING)
//    @Column(nullable = false)
//    private SlotStatus status = SlotStatus.AVAILABLE;
//
//    // Timestamp to track when a 'LOCKED' status should expire
//    private LocalDateTime lockedAt;
//
//    /**
//     * Logic to check if the slot time has already passed.
//     */
//    public boolean isExpired() {
//        return LocalDateTime.now().isAfter(this.startTime);
//    }
//}








package com.medibot.healthcare_platform.modules.doctor.entity;

import jakarta.persistence.*;
import lombok.*;
import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "availability_slots")
@Getter @Setter
@NoArgsConstructor @AllArgsConstructor
@Builder
public class Slot {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private UUID id;

    @ManyToOne(fetch = FetchType.EAGER) // Changed to EAGER for easier dashboard mapping
    @JoinColumn(name = "doctor_id", nullable = false)
    private Doctor doctor;

    @Column(nullable = false)
    private LocalDateTime startTime;

    @Column(nullable = false)
    private LocalDateTime endTime;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private SlotStatus status = SlotStatus.AVAILABLE;

    private LocalDateTime lockedAt;

    public boolean isExpired() {
        return LocalDateTime.now().isAfter(this.startTime);
    }
}