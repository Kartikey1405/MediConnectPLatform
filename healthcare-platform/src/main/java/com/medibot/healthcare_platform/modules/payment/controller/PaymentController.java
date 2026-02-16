//package com.medibot.healthcare_platform.modules.payment.controller;
//
//import com.medibot.healthcare_platform.modules.payment.service.PaymentService;
//import lombok.RequiredArgsConstructor;
//import org.springframework.http.ResponseEntity;
//import org.springframework.web.bind.annotation.*;
//
//import java.util.Map;
//import java.util.UUID;
//
//@RestController
//@RequestMapping("/api/payments")
//@RequiredArgsConstructor
//public class PaymentController {
//
//    private final PaymentService paymentService;
//
//    /**
//     * Updated: Frontend calls this to get a Razorpay Order ID.
//     * We add java.security.Principal to identify the logged-in patient.
//     */
//    @PostMapping("/create-order")
//    public ResponseEntity<String> createOrder(
//            @RequestParam UUID slotId,
//            @RequestParam Double amount,
//            java.security.Principal principal) { // Identifies the patient via JWT email
//        try {
//            // Pass the email to the service
//            return ResponseEntity.ok(paymentService.createOrder(slotId, amount, principal.getName()));
//        } catch (Exception e) {
//            return ResponseEntity.status(500).body(e.getMessage());
//        }
//    }
//
//    /**
//     * Step 2: Frontend calls this after the user completes the Razorpay popup.
//     */
//    @PostMapping("/verify-payment")
//    public ResponseEntity<String> verifyPayment(@RequestBody Map<String, String> data) {
//        try {
//            String orderId = data.get("razorpay_order_id");
//            String paymentId = data.get("razorpay_payment_id");
//            String signature = data.get("razorpay_signature");
//
//            paymentService.verifyPayment(orderId, paymentId, signature);
//            return ResponseEntity.ok("Payment successful and slot booked!");
//        } catch (Exception e) {
//            return ResponseEntity.status(400).body("Verification failed: " + e.getMessage());
//        }
//    }
//}






package com.medibot.healthcare_platform.modules.payment.controller;

import com.medibot.healthcare_platform.modules.payment.service.PaymentService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.security.Principal;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/payments")
@RequiredArgsConstructor
public class PaymentController {

    private final PaymentService paymentService;

    /**
     * Step 1: Create a Razorpay Order and link it to the current logged-in patient.
     * Identifying the patient here prevents the "null patient_id" error later.
     */
    @PostMapping("/create-order")
    public ResponseEntity<String> createOrder(
            @RequestParam UUID slotId,
            @RequestParam Double amount,
            Principal principal) { // Added Principal to identify the patient
        try {
            // principal.getName() retrieves the email from your JWT
            return ResponseEntity.ok(paymentService.createOrder(slotId, amount, principal.getName()));
        } catch (Exception e) {
            return ResponseEntity.status(500).body(e.getMessage());
        }
    }

    /**
     * Step 2: Verify the payment signature and finalize the booking.
     */
    @PostMapping("/verify-payment")
    public ResponseEntity<String> verifyPayment(@RequestBody Map<String, String> data) {
        try {
            String orderId = data.get("razorpay_order_id");
            String paymentId = data.get("razorpay_payment_id");
            String signature = data.get("razorpay_signature");

            paymentService.verifyPayment(orderId, paymentId, signature);
            return ResponseEntity.ok("Payment successful and slot booked!");
        } catch (Exception e) {
            return ResponseEntity.status(400).body("Verification failed: " + e.getMessage());
        }
    }
}