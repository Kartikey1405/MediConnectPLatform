package com.medibot.healthcare_platform.modules.booking.entity;

import com.medibot.healthcare_platform.modules.doctor.entity.Slot;
import com.medibot.healthcare_platform.modules.identity.entity.User;
import com.medibot.healthcare_platform.modules.payment.entity.TransactionLog;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "bookings")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class Booking {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "patient_id", nullable = false)
    private User patient;

    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "slot_id", nullable = false)
    private Slot slot;

    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "transaction_id")
    private TransactionLog transaction;

    @Enumerated(EnumType.STRING)
    private BookingStatus status;

    private String meetingLink;

    @CreationTimestamp
    private LocalDateTime createdAt;
}

