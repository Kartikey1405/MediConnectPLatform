//package com.medibot.healthcare_platform.modules.payment.service;
//
//import com.medibot.healthcare_platform.modules.doctor.entity.Slot;
//import com.medibot.healthcare_platform.modules.doctor.entity.SlotStatus;
//import com.medibot.healthcare_platform.modules.doctor.repository.SlotRepository;
//import com.medibot.healthcare_platform.modules.payment.entity.TransactionLog;
//import com.medibot.healthcare_platform.modules.payment.repository.TransactionLogRepository;
//import com.razorpay.Order;
//import com.razorpay.RazorpayClient;
//import com.razorpay.Utils;
//import lombok.RequiredArgsConstructor;
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
//public class PaymentService {
//
//    private final TransactionLogRepository transactionLogRepository;
//    private final SlotRepository slotRepository;
//
//    @Value("${razorpay.key.id}")
//    private String keyId;
//
//    @Value("${razorpay.key.secret}")
//    private String keySecret;
//
//    @Transactional
//    public String createOrder(UUID slotId, Double amount) throws Exception {
//        Slot slot = slotRepository.findById(slotId)
//                .orElseThrow(() -> new RuntimeException("Slot not found"));
//
//        if (slot.getStatus() != SlotStatus.AVAILABLE) {
//            throw new RuntimeException("Slot is no longer available");
//        }
//
//        RazorpayClient client = new RazorpayClient(keyId, keySecret);
//
//        JSONObject orderRequest = new JSONObject();
//        orderRequest.put("amount", amount * 100); // Amount in paise
//        orderRequest.put("currency", "INR");
//        orderRequest.put("receipt", slotId.toString());
//
//        Order order = client.orders.create(orderRequest);
//
//        // Lock the slot temporarily
//        slot.setStatus(SlotStatus.LOCKED);
//        slot.setLockedAt(LocalDateTime.now());
//        slotRepository.save(slot);
//
//        // Log the transaction attempt
//        TransactionLog log = TransactionLog.builder()
//                .slot(slot)
//                .razorpayOrderId(order.get("id"))
//                .amount(amount)
//                .status("CREATED")
//                .build();
//        transactionLogRepository.save(log);
//
//        return order.get("id");
//    }
//
//    @Transactional
//    public void verifyPayment(String orderId, String paymentId, String signature) throws Exception {
//        // Verify signature to prevent fraud
//        JSONObject attributes = new JSONObject();
//        attributes.put("razorpay_order_id", orderId);
//        attributes.put("razorpay_payment_id", paymentId);
//        attributes.put("razorpay_signature", signature);
//
//        boolean isValid = Utils.verifyPaymentSignature(attributes, keySecret);
//
//        if (isValid) {
//            TransactionLog log = transactionLogRepository.findByRazorpayOrderId(orderId)
//                    .orElseThrow(() -> new RuntimeException("Transaction not found"));
//
//            log.setStatus("SUCCESS");
//            log.setRazorpayPaymentId(paymentId);
//            log.setRazorpaySignature(signature);
//
//            // Logic to provide the meeting link (e.g., Jitsi or Zoom)
//            log.setMeetingLink("https://meet.medibot.com/" + UUID.randomUUID());
//
//            // Mark slot as occupied
//            Slot slot = log.getSlot();
//            slot.setStatus(SlotStatus.OCCUPIED);
//
//            slotRepository.save(slot);
//            transactionLogRepository.save(log);
//        } else {
//            throw new RuntimeException("Payment verification failed");
//        }
//    }
//}




package com.medibot.healthcare_platform.modules.payment.service;

import com.medibot.healthcare_platform.modules.booking.service.BookingService;
import com.medibot.healthcare_platform.modules.doctor.entity.Slot;
import com.medibot.healthcare_platform.modules.doctor.entity.SlotStatus;
import com.medibot.healthcare_platform.modules.doctor.repository.SlotRepository;
import com.medibot.healthcare_platform.modules.payment.entity.TransactionLog;
import com.medibot.healthcare_platform.modules.payment.repository.TransactionLogRepository;
import com.razorpay.RazorpayClient;
import com.razorpay.Utils;
import lombok.RequiredArgsConstructor;
import org.json.JSONObject; // Standard for Razorpay SDK
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class PaymentService {

    private final TransactionLogRepository transactionLogRepository;
    private final SlotRepository slotRepository;
    private final BookingService bookingService;

    @Value("${razorpay.key.id}")
    private String keyId;

    @Value("${razorpay.key.secret}")
    private String keySecret;

    @Transactional(rollbackFor = Exception.class)
    public String createOrder(UUID slotId, Double amount) throws Exception {
        Slot slot = slotRepository.findById(slotId)
                .orElseThrow(() -> new RuntimeException("Slot not found"));

        if (slot.getStatus() != SlotStatus.AVAILABLE) {
            throw new RuntimeException("Slot is no longer available.");
        }

        // Initialize Razorpay Client
        RazorpayClient client = new RazorpayClient(keyId, keySecret);

        // Prepare Order Request (Amount in paise)
        JSONObject orderRequest = new JSONObject();
        orderRequest.put("amount", (int)(amount * 100));
        orderRequest.put("currency", "INR");
        orderRequest.put("receipt", slotId.toString());

        // We use .toString() on the created object to safely get the Order ID
        // This avoids 'Order class not found' errors if your SDK uses generic Entity
        String orderId = client.orders.create(orderRequest).get("id");

        // Lock the slot
        slot.setStatus(SlotStatus.LOCKED);
        slot.setLockedAt(LocalDateTime.now());
        slotRepository.save(slot);

        // Log the transaction
        TransactionLog logEntry = TransactionLog.builder()
                .slot(slot)
                .razorpayOrderId(orderId)
                .amount(amount)
                .status("CREATED")
                .build();
        transactionLogRepository.save(logEntry);

        return orderId;
    }

    @Transactional(rollbackFor = Exception.class)
    public void verifyPayment(String orderId, String paymentId, String signature) throws Exception {
        JSONObject attributes = new JSONObject();
        attributes.put("razorpay_order_id", orderId);
        attributes.put("razorpay_payment_id", paymentId);
        attributes.put("razorpay_signature", signature);

        // Use Razorpay SDK Utils for signature verification
        boolean isValid = Utils.verifyPaymentSignature(attributes, keySecret);

        if (isValid) {
            TransactionLog logEntry = transactionLogRepository.findByRazorpayOrderId(orderId)
                    .orElseThrow(() -> new RuntimeException("Transaction not found"));

            logEntry.setStatus("SUCCESS");
            logEntry.setRazorpayPaymentId(paymentId);
            logEntry.setRazorpaySignature(signature);
            logEntry.setMeetingLink("https://meet.medibot.com/room-" + UUID.randomUUID());

            Slot slot = logEntry.getSlot();
            slot.setStatus(SlotStatus.OCCUPIED);
            slotRepository.save(slot);
            transactionLogRepository.save(logEntry);

            // Trigger Booking creation
            bookingService.confirmBooking(logEntry);

        } else {
            throw new RuntimeException("Payment verification failed.");
        }
    }
}