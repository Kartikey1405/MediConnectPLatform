//package com.medibot.healthcare_platform.modules.payment.repository;
//
//import com.medibot.healthcare_platform.modules.payment.entity.TransactionLog;
//import org.springframework.data.jpa.repository.JpaRepository;
//import java.util.Optional;
//import java.util.UUID;
//
//public interface TransactionLogRepository extends JpaRepository<TransactionLog, UUID> {
//    // Used during verification to find the log created during order generation
//    Optional<TransactionLog> findByRazorpayOrderId(String razorpayOrderId);
//}





package com.medibot.healthcare_platform.modules.payment.repository;

import com.medibot.healthcare_platform.modules.payment.entity.TransactionLog;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;
import java.util.UUID;

public interface TransactionLogRepository extends JpaRepository<TransactionLog, UUID> {
    // Finds the log created during order generation
    Optional<TransactionLog> findByRazorpayOrderId(String razorpayOrderId);

    // NEW: Used to check for and clear previous failed attempts for a specific slot
    Optional<TransactionLog> findBySlotId(UUID slotId);
}