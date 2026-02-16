//////
////////package com.medibot.healthcare_platform.modules.payment.service;
////////
////////import com.medibot.healthcare_platform.modules.booking.service.BookingService;
////////import com.medibot.healthcare_platform.modules.doctor.entity.Slot;
////////import com.medibot.healthcare_platform.modules.doctor.entity.SlotStatus;
////////import com.medibot.healthcare_platform.modules.doctor.repository.SlotRepository;
////////import com.medibot.healthcare_platform.modules.identity.entity.User;
////////import com.medibot.healthcare_platform.modules.identity.service.UserService; // Ensure this is imported
////////import com.medibot.healthcare_platform.modules.payment.entity.TransactionLog;
////////import com.medibot.healthcare_platform.modules.payment.repository.TransactionLogRepository;
////////import com.razorpay.RazorpayClient;
////////import com.razorpay.Utils;
////////import lombok.RequiredArgsConstructor;
////////import lombok.extern.slf4j.Slf4j;
////////import org.json.JSONObject;
////////import org.springframework.beans.factory.annotation.Value;
////////import org.springframework.stereotype.Service;
////////import org.springframework.transaction.annotation.Transactional;
////////
////////import java.time.LocalDateTime;
////////import java.util.UUID;
////////
////////@Service
////////@RequiredArgsConstructor
////////@Slf4j
////////public class PaymentService {
////////
////////    private final TransactionLogRepository transactionLogRepository;
////////    private final SlotRepository slotRepository;
////////    private final BookingService bookingService;
////////    private final UserService userService; // Fixed the red line dependency
////////
////////    @Value("${razorpay.key.id}")
////////    private String keyId;
////////
////////    @Value("${razorpay.key.secret}")
////////    private String keySecret;
////////
////////    /**
////////     * Step 1: Create Order and link the Patient.
////////     * Assigning 'patient' here prevents the NullConstraint error in the bookings table.
////////     */
////////    @Transactional(rollbackFor = Exception.class)
////////    public String createOrder(UUID slotId, Double amount, String userEmail) throws Exception {
////////        Slot slot = slotRepository.findById(slotId)
////////                .orElseThrow(() -> new RuntimeException("Slot not found"));
////////
////////        if (slot.getStatus() != SlotStatus.AVAILABLE) {
////////            throw new RuntimeException("Slot is no longer available.");
////////        }
////////
////////        // Resolve the red line: Fetching the User entity via the new method
////////        User patient = userService.getRawUserByEmail(userEmail);
////////
////////        RazorpayClient client = new RazorpayClient(keyId, keySecret);
////////        JSONObject orderRequest = new JSONObject();
////////        orderRequest.put("amount", (int)(amount * 100)); // Convert to paise
////////        orderRequest.put("currency", "INR");
////////        orderRequest.put("receipt", slotId.toString());
////////
////////        String orderId = client.orders.create(orderRequest).get("id").toString();
////////
////////        slot.setStatus(SlotStatus.LOCKED);
////////        slot.setLockedAt(LocalDateTime.now());
////////        slotRepository.save(slot);
////////
////////        // SAVE LOG: Linking the patient ensures Booking.builder() has a valid patient_id later.
////////        TransactionLog logEntry = TransactionLog.builder()
////////                .slot(slot)
////////                .patient(patient)
////////                .razorpayOrderId(orderId)
////////                .amount(amount)
////////                .status("CREATED")
////////                .build();
////////        transactionLogRepository.save(logEntry);
////////
////////        log.info("Order {} initialized for patient {}", orderId, userEmail);
////////        return orderId;
////////    }
////////
////////    /**
////////     * Step 2: Verification.
////////     */
////////    @Transactional(rollbackFor = Exception.class)
////////    public void verifyPayment(String orderId, String paymentId, String signature) throws Exception {
////////        JSONObject attributes = new JSONObject();
////////        attributes.put("razorpay_order_id", orderId);
////////        attributes.put("razorpay_payment_id", paymentId);
////////        attributes.put("razorpay_signature", signature);
////////
////////        boolean isValid = false;
////////        try {
////////            isValid = Utils.verifyPaymentSignature(attributes, keySecret);
////////        } catch (Exception e) {
////////            log.error("Signature verification logic error: {}", e.getMessage());
////////        }
////////
////////        if (isValid) {
////////            TransactionLog logEntry = transactionLogRepository.findByRazorpayOrderId(orderId)
////////                    .orElseThrow(() -> new RuntimeException("Transaction not found for ID: " + orderId));
////////
////////            logEntry.setStatus("SUCCESS");
////////            logEntry.setRazorpayPaymentId(paymentId);
////////            logEntry.setRazorpaySignature(signature);
////////            logEntry.setMeetingLink("https://meet.medibot.com/room-" + UUID.randomUUID());
////////
////////            Slot slot = logEntry.getSlot();
////////            slot.setStatus(SlotStatus.OCCUPIED);
////////
////////            slotRepository.save(slot);
////////            transactionLogRepository.save(logEntry);
////////
////////            // This now safe because logEntry.getPatient() is NOT null
////////            bookingService.confirmBooking(logEntry);
////////            log.info("Booking confirmed successfully for order: {}", orderId);
////////
////////        } else {
////////            log.error("Signature mismatch for Order: {}", orderId);
////////            throw new RuntimeException("Payment verification failed.");
////////        }
////////    }
////////}
//////
//////
//////
//////
//////
//////
//////
//////
//////
//////
//////
//////
//////
//////package com.medibot.healthcare_platform.modules.payment.service;
//////
//////import com.medibot.healthcare_platform.modules.booking.service.BookingService;
//////import com.medibot.healthcare_platform.modules.doctor.entity.Slot;
//////import com.medibot.healthcare_platform.modules.doctor.entity.SlotStatus;
//////import com.medibot.healthcare_platform.modules.doctor.repository.SlotRepository;
//////import com.medibot.healthcare_platform.modules.identity.entity.User;
//////import com.medibot.healthcare_platform.modules.identity.service.UserService;
//////import com.medibot.healthcare_platform.modules.payment.entity.TransactionLog;
//////import com.medibot.healthcare_platform.modules.payment.repository.TransactionLogRepository;
//////import com.razorpay.RazorpayClient;
//////import com.razorpay.Utils;
//////import lombok.RequiredArgsConstructor;
//////import lombok.extern.slf4j.Slf4j;
//////import org.json.JSONObject;
//////import org.springframework.beans.factory.annotation.Value;
//////import org.springframework.stereotype.Service;
//////import org.springframework.transaction.annotation.Transactional;
//////
//////import java.time.LocalDateTime;
//////import java.util.UUID;
//////
//////@Service
//////@RequiredArgsConstructor
//////@Slf4j
//////public class PaymentService {
//////
//////    private final TransactionLogRepository transactionLogRepository;
//////    private final SlotRepository slotRepository;
//////    private final BookingService bookingService;
//////    private final UserService userService;
//////
//////    @Value("${razorpay.key.id}")
//////    private String keyId;
//////
//////    @Value("${razorpay.key.secret}")
//////    private String keySecret;
//////
//////    /**
//////     * Step 1: Initialize the Razorpay Order and lock the doctor's slot.
//////     * Assigning the 'patient' here ensures that the final booking creation
//////     * does not fail due to a null patient_id constraint.
//////     */
//////    @Transactional(rollbackFor = Exception.class)
//////    public String createOrder(UUID slotId, Double amount, String userEmail) throws Exception {
//////        Slot slot = slotRepository.findById(slotId)
//////                .orElseThrow(() -> new RuntimeException("Slot not found"));
//////
//////        if (slot.getStatus() != SlotStatus.AVAILABLE) {
//////            throw new RuntimeException("Slot is no longer available.");
//////        }
//////
//////        // Fetch the Patient entity from the identity module
//////        User patient = userService.getRawUserByEmail(userEmail);
//////
//////        RazorpayClient client = new RazorpayClient(keyId, keySecret);
//////        JSONObject orderRequest = new JSONObject();
//////        orderRequest.put("amount", (int)(amount * 100)); // Amount in paise for precision
//////        orderRequest.put("currency", "INR");
//////        orderRequest.put("receipt", slotId.toString());
//////
//////        String orderId = client.orders.create(orderRequest).get("id").toString();
//////
//////        // Lock the slot temporarily to prevent double-booking during checkout
//////        slot.setStatus(SlotStatus.LOCKED);
//////        slot.setLockedAt(LocalDateTime.now());
//////        slotRepository.save(slot);
//////
//////        // Link the patient to the TransactionLog record immediately
//////        TransactionLog logEntry = TransactionLog.builder()
//////                .slot(slot)
//////                .patient(patient)
//////                .razorpayOrderId(orderId)
//////                .amount(amount)
//////                .status("CREATED")
//////                .build();
//////        transactionLogRepository.save(logEntry);
//////
//////        log.info("Order {} initialized for patient: {}", orderId, userEmail);
//////        return orderId;
//////    }
//////
//////    /**
//////     * Step 2: Verify the security signature and finalize the booking.
//////     * Uses the JSONObject verification method required by the Java SDK.
//////     */
//////    @Transactional(rollbackFor = Exception.class)
//////    public void verifyPayment(String orderId, String paymentId, String signature) throws Exception {
//////        // Construct verification attributes for the SDK
//////        JSONObject attributes = new JSONObject();
//////        attributes.put("razorpay_order_id", orderId);
//////        attributes.put("razorpay_payment_id", paymentId);
//////        attributes.put("razorpay_signature", signature);
//////
//////        boolean isValid = false;
//////        try {
//////            // SDK signature check using your RAZORPAY_KEY_SECRET
//////            isValid = Utils.verifyPaymentSignature(attributes, keySecret);
//////        } catch (Exception e) {
//////            log.error("Internal Signature Verification Failure: {}", e.getMessage());
//////        }
//////
//////        if (isValid) {
//////            TransactionLog logEntry = transactionLogRepository.findByRazorpayOrderId(orderId)
//////                    .orElseThrow(() -> new RuntimeException("Transaction not found for ID: " + orderId));
//////
//////            logEntry.setStatus("SUCCESS");
//////            logEntry.setRazorpayPaymentId(paymentId);
//////            logEntry.setRazorpaySignature(signature);
//////
//////            // Generate a real public meeting room link to avoid SSL unrecognized name alerts
//////            logEntry.setMeetingLink("https://meet.jit.si/Medibot-Room-" + UUID.randomUUID());
//////
//////            // Mark slot as officially OCCUPIED
//////            Slot slot = logEntry.getSlot();
//////            slot.setStatus(SlotStatus.OCCUPIED);
//////
//////            slotRepository.save(slot);
//////            transactionLogRepository.save(logEntry);
//////
//////            // Confirm booking (Patient is now safely attached to logEntry)
//////            bookingService.confirmBooking(logEntry);
//////            log.info("Payment Verified. Booking confirmed for order: {}", orderId);
//////
//////        } else {
//////            log.error("SECURITY ALERT: Signature mismatch for Order: {}. Verification failed.", orderId);
//////            throw new RuntimeException("Payment verification failed. Security mismatch.");
//////        }
//////    }
//////}
////
////
////
////
////package com.medibot.healthcare_platform.modules.payment.service;
////
////import com.medibot.healthcare_platform.modules.booking.service.BookingService;
////import com.medibot.healthcare_platform.modules.doctor.entity.Slot;
////import com.medibot.healthcare_platform.modules.doctor.entity.SlotStatus;
////import com.medibot.healthcare_platform.modules.doctor.repository.SlotRepository;
////import com.medibot.healthcare_platform.modules.identity.entity.User;
////import com.medibot.healthcare_platform.modules.identity.service.UserService;
////import com.medibot.healthcare_platform.modules.payment.entity.TransactionLog;
////import com.medibot.healthcare_platform.modules.payment.repository.TransactionLogRepository;
////import com.razorpay.RazorpayClient;
////import com.razorpay.Utils;
////import lombok.RequiredArgsConstructor;
////import lombok.extern.slf4j.Slf4j;
////import org.json.JSONObject;
////import org.springframework.beans.factory.annotation.Value;
////import org.springframework.stereotype.Service;
////import org.springframework.transaction.annotation.Transactional;
////
////import java.time.LocalDateTime;
////import java.util.UUID;
////
////@Service
////@RequiredArgsConstructor
////@Slf4j
////public class PaymentService {
////
////    private final TransactionLogRepository transactionLogRepository;
////    private final SlotRepository slotRepository;
////    private final BookingService bookingService;
////    private final UserService userService;
////
////    @Value("${razorpay.key.id}")
////    private String keyId;
////
////    @Value("${razorpay.key.secret}")
////    private String keySecret;
////
////    /**
////     * Step 1: Initialize Razorpay Order and link the Patient.
////     * Linking 'patient' here ensures 'confirmBooking' has the identity needed for the DB constraint.
////     */
////    @Transactional(rollbackFor = Exception.class)
////    public String createOrder(UUID slotId, Double amount, String userEmail) throws Exception {
////        Slot slot = slotRepository.findById(slotId)
////                .orElseThrow(() -> new RuntimeException("Slot not found"));
////
////        if (slot.getStatus() != SlotStatus.AVAILABLE) {
////            throw new RuntimeException("Slot is no longer available.");
////        }
////
////        // Identify the patient from security context/email
////        User patient = userService.getRawUserByEmail(userEmail);
////
////        RazorpayClient client = new RazorpayClient(keyId, keySecret);
////        JSONObject orderRequest = new JSONObject();
////
////        // Use Math.round to avoid floating point issues during conversion to paise
////        orderRequest.put("amount", Math.round(amount * 100));
////        orderRequest.put("currency", "INR");
////        orderRequest.put("receipt", slotId.toString());
////
////        // Extract ID and convert to String safely
////        var order = client.orders.create(orderRequest);
////        String orderId = order.get("id").toString();
////
////        // Lock slot to prevent double-booking during payment window
////        slot.setStatus(SlotStatus.LOCKED);
////        slot.setLockedAt(LocalDateTime.now());
////        slotRepository.save(slot);
////
////        // Populate TransactionLog with Patient link to satisfy Not-Null constraint in Bookings
////        TransactionLog logEntry = TransactionLog.builder()
////                .slot(slot)
////                .patient(patient)
////                .razorpayOrderId(orderId)
////                .amount(amount)
////                .status("CREATED")
////                .build();
////        transactionLogRepository.save(logEntry);
////
////        log.info("Handshake Initialized: Order {} created for patient: {}", orderId, userEmail);
////        return orderId;
////    }
////
////    /**
////     * Step 2: Verify the security signature and convert transaction to a confirmed Booking.
////     */
////    @Transactional(rollbackFor = Exception.class)
////    public void verifyPayment(String orderId, String paymentId, String signature) throws Exception {
////        // Construct the expected attributes for HMAC verification
////        JSONObject attributes = new JSONObject();
////        attributes.put("razorpay_order_id", orderId);
////        attributes.put("razorpay_payment_id", paymentId);
////        attributes.put("razorpay_signature", signature);
////
////        boolean isValid = false;
////        try {
////            // SDK-native signature check
////            isValid = Utils.verifyPaymentSignature(attributes, keySecret);
////        } catch (Exception e) {
////            log.error("Security verification logic failure: {}", e.getMessage());
////        }
////
////        if (isValid) {
////            TransactionLog logEntry = transactionLogRepository.findByRazorpayOrderId(orderId)
////                    .orElseThrow(() -> new RuntimeException("Transaction not found for ID: " + orderId));
////
////            logEntry.setStatus("SUCCESS");
////            logEntry.setRazorpayPaymentId(paymentId);
////            logEntry.setRazorpaySignature(signature);
////
////            // Public Jitsi domain ensures no SSL errors during the video call
////            logEntry.setMeetingLink("https://meet.jit.si/Medibot-Room-" + UUID.randomUUID());
////
////            // Finalize Slot and Log status
////            Slot slot = logEntry.getSlot();
////            slot.setStatus(SlotStatus.OCCUPIED);
////
////            slotRepository.save(slot);
////            transactionLogRepository.save(logEntry);
////
////            // Successfully links patient and slot into the final Booking entity
////            bookingService.confirmBooking(logEntry);
////            log.info("Verification Success: Booking confirmed for order: {}", orderId);
////
////        } else {
////            log.error("SECURITY ALERT: Invalid signature detected for Order: {}", orderId);
////            throw new RuntimeException("Payment verification failed. Security mismatch.");
////        }
////    }
////}
//
//
//
//
//package com.medibot.healthcare_platform.modules.payment.service;
//
//import com.medibot.healthcare_platform.modules.booking.service.BookingService;
//import com.medibot.healthcare_platform.modules.doctor.entity.Slot;
//import com.medibot.healthcare_platform.modules.doctor.entity.SlotStatus;
//import com.medibot.healthcare_platform.modules.doctor.repository.SlotRepository;
//import com.medibot.healthcare_platform.modules.identity.entity.User;
//import com.medibot.healthcare_platform.modules.identity.service.UserService;
//import com.medibot.healthcare_platform.modules.payment.entity.TransactionLog;
//import com.medibot.healthcare_platform.modules.payment.repository.TransactionLogRepository;
//import com.razorpay.RazorpayClient;
//import com.razorpay.Utils;
//import lombok.RequiredArgsConstructor;
//import lombok.extern.slf4j.Slf4j;
//import org.json.JSONObject;
//import org.springframework.beans.factory.annotation.Value;
//import org.springframework.stereotype.Service;
//import org.springframework.transaction.annotation.Transactional;
//
//import java.time.LocalDateTime;
//import java.util.UUID;
//
//@Service
//@RequiredArgsConstructor
//@Slf4j
//public class PaymentService {
//
//    private final TransactionLogRepository transactionLogRepository;
//    private final SlotRepository slotRepository;
//    private final BookingService bookingService;
//    private final UserService userService;
//
//    @Value("${razorpay.key.id}")
//    private String keyId;
//
//    @Value("${razorpay.key.secret}")
//    private String keySecret;
//
//    /**
//     * Step 1: Initialize Razorpay Order.
//     * Fix: Clears existing transaction logs for the slot to avoid Duplicate Key errors.
//     */
//    @Transactional(rollbackFor = Exception.class)
//    public String createOrder(UUID slotId, Double amount, String userEmail) throws Exception {
//        Slot slot = slotRepository.findById(slotId)
//                .orElseThrow(() -> new RuntimeException("Slot not found"));
//
//        // Only allow booking if the slot is AVAILABLE (Cleanup service handles expired locks)
//        if (slot.getStatus() != SlotStatus.AVAILABLE) {
//            throw new RuntimeException("Slot is no longer available.");
//        }
//
//        // FETCH PATIENT: Essential for linking the final booking
//        User patient = userService.getRawUserByEmail(userEmail);
//
//        // FIX: Remove previous failed attempts for this slot to avoid Unique Constraint violation
//        transactionLogRepository.findBySlotId(slotId).ifPresent(transactionLogRepository::delete);
//
//        RazorpayClient client = new RazorpayClient(keyId, keySecret);
//        JSONObject orderRequest = new JSONObject();
//        orderRequest.put("amount", Math.round(amount * 100)); // Precise paise conversion
//        orderRequest.put("currency", "INR");
//        orderRequest.put("receipt", slotId.toString());
//
//        String orderId = client.orders.create(orderRequest).get("id").toString();
//
//        // Lock the slot
//        slot.setStatus(SlotStatus.LOCKED);
//        slot.setLockedAt(LocalDateTime.now());
//        slotRepository.save(slot);
//
//        // Create fresh log entry with patient link
//        TransactionLog logEntry = TransactionLog.builder()
//                .slot(slot)
//                .patient(patient)
//                .razorpayOrderId(orderId)
//                .amount(amount)
//                .status("CREATED")
//                .build();
//        transactionLogRepository.save(logEntry);
//
//        log.info("Fresh Handshake: Order {} created for slot {}", orderId, slotId);
//        return orderId;
//    }
//
//    /**
//     * Step 2: Verify and Finalize.
//     */
//    @Transactional(rollbackFor = Exception.class)
//    public void verifyPayment(String orderId, String paymentId, String signature) throws Exception {
//        JSONObject attributes = new JSONObject();
//        attributes.put("razorpay_order_id", orderId);
//        attributes.put("razorpay_payment_id", paymentId);
//        attributes.put("razorpay_signature", signature);
//
//        boolean isValid = false;
//        try {
//            isValid = Utils.verifyPaymentSignature(attributes, keySecret);
//        } catch (Exception e) {
//            log.error("Signature verification logic failure: {}", e.getMessage());
//        }
//
//        if (isValid) {
//            TransactionLog logEntry = transactionLogRepository.findByRazorpayOrderId(orderId)
//                    .orElseThrow(() -> new RuntimeException("Transaction not found for ID: " + orderId));
//
//            logEntry.setStatus("SUCCESS");
//            logEntry.setRazorpayPaymentId(paymentId);
//            logEntry.setRazorpaySignature(signature);
//
//            // Real Jitsi domain fixes the SSL Unrecognized Name error
//            logEntry.setMeetingLink("https://meet.jit.si/Medibot-Room-" + UUID.randomUUID());
//
//            Slot slot = logEntry.getSlot();
//            slot.setStatus(SlotStatus.OCCUPIED);
//
//            slotRepository.save(slot);
//            transactionLogRepository.save(logEntry);
//
//            // Confirms the booking with the pre-linked patient
//            bookingService.confirmBooking(logEntry);
//            log.info("Booking finalized successfully for order: {}", orderId);
//
//        } else {
//            log.error("SECURITY ALERT: Signature mismatch for Order: {}", orderId);
//            throw new RuntimeException("Payment verification failed. Security mismatch.");
//        }
//    }
//}
























package com.medibot.healthcare_platform.modules.payment.service;

import com.medibot.healthcare_platform.modules.booking.service.BookingService;
import com.medibot.healthcare_platform.modules.doctor.entity.Slot;
import com.medibot.healthcare_platform.modules.doctor.entity.SlotStatus;
import com.medibot.healthcare_platform.modules.doctor.repository.SlotRepository;
import com.medibot.healthcare_platform.modules.identity.entity.User;
import com.medibot.healthcare_platform.modules.identity.service.UserService;
import com.medibot.healthcare_platform.modules.payment.entity.TransactionLog;
import com.medibot.healthcare_platform.modules.payment.repository.TransactionLogRepository;
import com.razorpay.RazorpayClient;
import com.razorpay.Utils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class PaymentService {

    private final TransactionLogRepository transactionLogRepository;
    private final SlotRepository slotRepository;
    private final BookingService bookingService;
    private final UserService userService;

    @Value("${razorpay.key.id}")
    private String keyId;

    @Value("${razorpay.key.secret}")
    private String keySecret;

    /**
     * Step 1: Initialize the Razorpay Order and link the Patient.
     * RESOLVED: Clears existing transaction logs for the slot to avoid Duplicate Key errors.
     */
    @Transactional(rollbackFor = Exception.class)
    public String createOrder(UUID slotId, Double amount, String userEmail) throws Exception {
        // 1. Validate Slot Existence
        Slot slot = slotRepository.findById(slotId)
                .orElseThrow(() -> new RuntimeException("Slot not found"));

        // 2. Validate Slot Availability
        // Note: SlotCleanupService is responsible for releasing expired LOCKED slots.
        if (slot.getStatus() != SlotStatus.AVAILABLE) {
            throw new RuntimeException("Slot is currently unavailable (locked or occupied).");
        }

        // 3. Identify Patient (Fixes 'null patient_id' error later)
        User patient = userService.getRawUserByEmail(userEmail);

        // 4. FIX: Remove any previous failed/incomplete attempts for this specific slot.
        // This removes the OneToOne unique constraint violation.
        transactionLogRepository.findBySlotId(slotId).ifPresent(logEntry -> {
            log.info("Removing stale transaction log for slot: {}", slotId);
            transactionLogRepository.delete(logEntry);
        });

        // 5. Razorpay Handshake
        RazorpayClient client = new RazorpayClient(keyId, keySecret);
        JSONObject orderRequest = new JSONObject();

        // Use Math.round for precise paise conversion to prevent amount mismatch errors.
        orderRequest.put("amount", Math.round(amount * 100));
        orderRequest.put("currency", "INR");
        orderRequest.put("receipt", slotId.toString());

        // Extract fresh Order ID
        String orderId = client.orders.create(orderRequest).get("id").toString();

        // 6. State Management: Lock the slot for the payment duration
        slot.setStatus(SlotStatus.LOCKED);
        slot.setLockedAt(LocalDateTime.now());
        slotRepository.save(slot);

        // 7. Persistent Audit Log: Link patient and slot for the final booking step
        TransactionLog logEntry = TransactionLog.builder()
                .slot(slot)
                .patient(patient)
                .razorpayOrderId(orderId)
                .amount(amount)
                .status("CREATED")
                .build();
        transactionLogRepository.save(logEntry);

        log.info("Order {} initialized for slot {}", orderId, slotId);
        return orderId;
    }

    /**
     * Step 2: Verify the security signature and finalize the booking.
     * RESOLVED: Uses JSONObject verification to fix 'String provided instead of JSONObject' error.
     */
    @Transactional(rollbackFor = Exception.class)
    public void verifyPayment(String orderId, String paymentId, String signature) throws Exception {
        // Prepare payload for HMAC verification
        JSONObject attributes = new JSONObject();
        attributes.put("razorpay_order_id", orderId);
        attributes.put("razorpay_payment_id", paymentId);
        attributes.put("razorpay_signature", signature);

        boolean isValid = false;
        try {
            // SDK signature check
            isValid = Utils.verifyPaymentSignature(attributes, keySecret);
        } catch (Exception e) {
            log.error("Internal Signature Verification logic crashed: {}", e.getMessage());
        }

        if (isValid) {
            TransactionLog logEntry = transactionLogRepository.findByRazorpayOrderId(orderId)
                    .orElseThrow(() -> new RuntimeException("Transaction records not found for order: " + orderId));

            // 1. Update Transaction Details
            logEntry.setStatus("SUCCESS");
            logEntry.setRazorpayPaymentId(paymentId);
            logEntry.setRazorpaySignature(signature);

            // 2. FIX: Use real public domain to avoid ERR_SSL_UNRECOGNIZED_NAME_ALERT.
            logEntry.setMeetingLink("https://meet.jit.si/Medibot-Room-" + UUID.randomUUID());

            // 3. Finalize Slot State
            Slot slot = logEntry.getSlot();
            slot.setStatus(SlotStatus.OCCUPIED);

            slotRepository.save(slot);
            transactionLogRepository.save(logEntry);

            // 4. Clinical Handover: Create the finalized Booking entity
            // This is now safe because 'logEntry.getPatient()' was saved in Step 1.
            bookingService.confirmBooking(logEntry);
            log.info("SUCCESS: Booking confirmed for order {}", orderId);

        } else {
            log.error("SECURITY ALERT: Signature mismatch for Order: {}. Transaction rejected.", orderId);
            throw new RuntimeException("Payment verification failed. Security mismatch.");
        }
    }
}