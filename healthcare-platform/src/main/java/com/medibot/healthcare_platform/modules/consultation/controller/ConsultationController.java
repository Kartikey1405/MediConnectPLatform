//////////package com.medibot.healthcare_platform.modules.consultation.controller;
//////////
//////////import com.medibot.healthcare_platform.modules.consultation.entity.Consultation;
//////////import com.medibot.healthcare_platform.modules.consultation.service.ConsultationService;
//////////import lombok.RequiredArgsConstructor;
//////////import org.springframework.http.ResponseEntity;
//////////import org.springframework.security.access.prepost.PreAuthorize;
//////////import org.springframework.web.bind.annotation.*;
//////////import java.util.UUID;
//////////
//////////@RestController
//////////@RequestMapping("/api/consultations")
//////////@RequiredArgsConstructor
//////////public class ConsultationController {
//////////    private final ConsultationService consultationService;
//////////
//////////    @PostMapping("/start/{bookingId}")
//////////    @PreAuthorize("hasRole('DOCTOR')")
//////////    public ResponseEntity<Consultation> start(@PathVariable UUID bookingId) {
//////////        return ResponseEntity.ok(consultationService.startConsultation(bookingId));
//////////    }
//////////
//////////    @PatchMapping("/end/{id}")
//////////    @PreAuthorize("hasRole('DOCTOR')")
//////////    public ResponseEntity<String> end(@PathVariable UUID id, @RequestBody String notes) {
//////////        consultationService.endConsultation(id, notes);
//////////        return ResponseEntity.ok("Consultation ended and notes saved.");
//////////    }
//////////}
////////
////////
////////
////////
////////package com.medibot.healthcare_platform.modules.consultation.controller;
////////
////////import com.medibot.healthcare_platform.modules.consultation.entity.Consultation;
////////import com.medibot.healthcare_platform.modules.consultation.service.ConsultationService;
////////import lombok.RequiredArgsConstructor;
////////import org.springframework.http.ResponseEntity;
////////import org.springframework.security.access.prepost.PreAuthorize;
////////import org.springframework.web.bind.annotation.*;
////////import java.util.List;
////////import java.util.UUID;
////////
////////@RestController
////////@RequestMapping("/api/consultations")
////////@RequiredArgsConstructor
////////public class ConsultationController {
////////    private final ConsultationService consultationService;
////////
////////    @PostMapping("/start/{bookingId}")
////////    @PreAuthorize("hasRole('DOCTOR')")
////////    public ResponseEntity<Consultation> start(@PathVariable UUID bookingId) {
////////        return ResponseEntity.ok(consultationService.startConsultation(bookingId));
////////    }
////////
////////    @PatchMapping("/end/{id}")
////////    @PreAuthorize("hasRole('DOCTOR')")
////////    public ResponseEntity<String> end(@PathVariable UUID id, @RequestBody String notes) {
////////        consultationService.endConsultation(id, notes);
////////        return ResponseEntity.ok("Consultation ended and notes saved.");
////////    }
////////
////////    /**
////////     * NEW: Endpoint for Patients to view their verified medical notes.
////////     */
////////    @GetMapping("/patient/{patientId}")
////////    @PreAuthorize("hasRole('PATIENT') or hasRole('ADMIN')")
////////    public ResponseEntity<List<Consultation>> getHistory(@PathVariable UUID patientId) {
////////        return ResponseEntity.ok(consultationService.getPatientConsultationHistory(patientId));
////////    }
////////
////////    // Allows the doctor to "broadcast" the room ID they just joined
////////    @PatchMapping("/{consultationId}/room/{roomId}")
////////    public ResponseEntity<?> updateRoomId(@PathVariable UUID consultationId, @PathVariable String roomId) {
////////        consultationService.updateRoomId(consultationId, roomId);
////////        return ResponseEntity.ok().build();
////////    }
////////
////////    // Allows the patient to "discover" which room the doctor is in
////////    @GetMapping("/active/{bookingId}")
////////    public ResponseEntity<String> getActiveRoom(@PathVariable UUID bookingId) {
////////        return ResponseEntity.ok(consultationService.getRoomIdByBooking(bookingId));
////////    }
////////}
//////
//////package com.medibot.healthcare_platform.modules.consultation.controller;
//////
//////import com.medibot.healthcare_platform.modules.consultation.entity.Consultation;
//////import com.medibot.healthcare_platform.modules.consultation.service.ConsultationService;
//////import lombok.RequiredArgsConstructor;
//////import org.springframework.http.HttpStatus;
//////import org.springframework.http.ResponseEntity;
//////import org.springframework.security.access.prepost.PreAuthorize;
//////import org.springframework.web.bind.annotation.*;
//////
//////import java.util.List;
//////import java.util.UUID;
//////
//////@RestController
//////@RequestMapping("/api/consultations")
//////@RequiredArgsConstructor
//////public class ConsultationController {
//////    private final ConsultationService consultationService;
//////
//////    /**
//////     * HANDSHAKE START:
//////     * Used by both Doctor and Patient to enter the context of the call.
//////     */
//////    @PostMapping("/start/{bookingId}")
//////    @PreAuthorize("hasAnyRole('DOCTOR', 'PATIENT')")
//////    public ResponseEntity<Consultation> start(@PathVariable UUID bookingId) {
//////        return ResponseEntity.ok(consultationService.startConsultation(bookingId));
//////    }
//////
//////    /**
//////     * ROOM BROADCAST:
//////     * Dr. Elena calls this to "pin" the authoritative Jitsi Room ID to the database.
//////     */
//////    @PatchMapping("/{consultationId}/room")
//////    @PreAuthorize("hasRole('DOCTOR')")
//////    public ResponseEntity<Void> updateRoomId(@PathVariable UUID consultationId, @RequestBody String roomId) {
//////        consultationService.updateRoomId(consultationId, roomId);
//////        return ResponseEntity.ok().build();
//////    }
//////
//////    /**
//////     * ROOM DISCOVERY:
//////     * Kartik calls this to find exactly which room Elena has created.
//////     */
//////    @GetMapping("/active/{bookingId}")
//////    @PreAuthorize("hasRole('PATIENT')")
//////    public ResponseEntity<String> getActiveRoom(@PathVariable UUID bookingId) {
//////        try {
//////            return ResponseEntity.ok(consultationService.getRoomIdByBooking(bookingId));
//////        } catch (RuntimeException e) {
//////            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(e.getMessage());
//////        }
//////    }
//////
//////    /**
//////     * WRAP-UP:
//////     * Finalizes the notes and triggers the slot release.
//////     */
//////    @PatchMapping("/end/{id}")
//////    @PreAuthorize("hasRole('DOCTOR')")
//////    public ResponseEntity<String> end(@PathVariable UUID id, @RequestBody String notes) {
//////        consultationService.endConsultation(id, notes);
//////        return ResponseEntity.ok("Consultation archived and slot released.");
//////    }
//////
//////    /**
//////     * HISTORY:
//////     * Used by the Patient Dashboard to show the Medical Records library.
//////     */
//////    @GetMapping("/patient/{patientId}")
//////    @PreAuthorize("hasRole('PATIENT') or hasRole('ADMIN')")
//////    public ResponseEntity<List<Consultation>> getHistory(@PathVariable UUID patientId) {
//////        return ResponseEntity.ok(consultationService.getPatientConsultationHistory(patientId));
//////    }
//////
//////
//////}
////
////
////package com.medibot.healthcare_platform.modules.consultation.controller;
////
////import com.medibot.healthcare_platform.modules.consultation.entity.Consultation;
////import com.medibot.healthcare_platform.modules.consultation.service.ConsultationService;
////import lombok.RequiredArgsConstructor;
////import org.springframework.http.HttpStatus;
////import org.springframework.http.ResponseEntity;
////import org.springframework.security.access.prepost.PreAuthorize;
////import org.springframework.web.bind.annotation.*;
////
////import java.util.List;
////import java.util.UUID;
////
////@RestController
////@RequestMapping("/api/consultations")
////@RequiredArgsConstructor
////public class ConsultationController {
////    private final ConsultationService consultationService;
////
////    /**
////     * 1. HANDSHAKE START
////     * Initializes the database record. Now allows PATIENT access so Kartik
////     * can initialize the handshake context if he arrives first.
////     */
////    @PostMapping("/start/{bookingId}")
////    @PreAuthorize("hasAnyRole('DOCTOR', 'PATIENT')")
////    public ResponseEntity<Consultation> start(@PathVariable UUID bookingId) {
////        return ResponseEntity.ok(consultationService.startConsultation(bookingId));
////    }
////
////    /**
////     * 2. ROOM BROADCAST (The "Elena" Endpoint)
////     * Dr. Elena calls this once she enters Jitsi to save the exact room string.
////     */
////    @PatchMapping("/{consultationId}/room")
////    @PreAuthorize("hasRole('DOCTOR')")
////    public ResponseEntity<Void> updateRoomId(@PathVariable UUID consultationId, @RequestBody String roomId) {
////        consultationService.updateRoomId(consultationId, roomId);
////        return ResponseEntity.ok().build();
////    }
////
////    /**
////     * 3. ROOM DISCOVERY (The "Kartik" Endpoint)
////     * Kartik calls this to fetch the exact room Dr. Elena is waiting in.
////     */
////    @GetMapping("/active/{bookingId}")
////    @PreAuthorize("hasRole('PATIENT')")
////    public ResponseEntity<String> getActiveRoom(@PathVariable UUID bookingId) {
////        try {
////            return ResponseEntity.ok(consultationService.getRoomIdByBooking(bookingId));
////        } catch (RuntimeException e) {
////            // Returns 404 so the Frontend can show "Waiting for Doctor..."
////            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(e.getMessage());
////        }
////    }
////
////    /**
////     * 4. SESSION WRAP-UP
////     * Finalizes notes and releases the slot status back to AVAILABLE.
////     */
////    @PatchMapping("/end/{id}")
////    @PreAuthorize("hasRole('DOCTOR')")
////    public ResponseEntity<String> end(@PathVariable UUID id, @RequestBody String notes) {
////        consultationService.endConsultation(id, notes);
////        return ResponseEntity.ok("Consultation archived and slot released.");
////    }
////
////    /**
////     * 5. CLINICAL HISTORY
////     * Fetches all verified records for the Patient's medical vault.
////     */
////    @GetMapping("/patient/{patientId}")
////    @PreAuthorize("hasRole('PATIENT') or hasRole('ADMIN')")
////    public ResponseEntity<List<Consultation>> getHistory(@PathVariable UUID patientId) {
////        return ResponseEntity.ok(consultationService.getPatientConsultationHistory(patientId));
////    }
////}
//
//
//
//package com.medibot.healthcare_platform.modules.consultation.controller;
//
//import com.medibot.healthcare_platform.modules.consultation.dto.PrescriptionRequest;
//import com.medibot.healthcare_platform.modules.consultation.entity.Consultation;
//import com.medibot.healthcare_platform.modules.consultation.service.ConsultationService;
//import lombok.RequiredArgsConstructor;
//import org.springframework.http.HttpStatus;
//import org.springframework.http.ResponseEntity;
//import org.springframework.security.access.prepost.PreAuthorize;
//import org.springframework.web.bind.annotation.*;
//
//import java.util.List;
//import java.util.UUID;
//
//@RestController
//@RequestMapping("/api/consultations")
//@RequiredArgsConstructor
//public class ConsultationController {
//    private final ConsultationService consultationService;
//
//    /**
//     * 1. HANDSHAKE START: Initializes the context.
//     * Accessible by both to ensure the session object exists before discovery.
//     */
//    @PostMapping("/start/{bookingId}")
//    @PreAuthorize("hasAnyRole('DOCTOR', 'PATIENT')")
//    public ResponseEntity<Consultation> start(@PathVariable UUID bookingId) {
//        return ResponseEntity.ok(consultationService.startConsultation(bookingId));
//    }
//
//    /**
//     * 2. ROOM BROADCAST (Dr. Elena): Pins the Jitsi ID.
//     * Consumes plain text to avoid '400 Bad Request' from raw string payloads.
//     */
//    @PatchMapping(value = "/{consultationId}/room", consumes = {"text/plain", "application/json"})
//    @PreAuthorize("hasRole('DOCTOR')")
//    public ResponseEntity<Void> updateRoomId(@PathVariable UUID consultationId, @RequestBody String roomId) {
//        // Clean potential extra quotes from the frontend payload
//        String cleanRoomId = roomId.replace("\"", "");
//        consultationService.updateRoomId(consultationId, cleanRoomId);
//        return ResponseEntity.ok().build();
//    }
//
//    /**
//     * 3. ROOM DISCOVERY (Kartik): Finds Elena's room.
//     */
//    @GetMapping("/active/{bookingId}")
//    @PreAuthorize("hasRole('PATIENT')")
//    public ResponseEntity<String> getActiveRoom(@PathVariable UUID bookingId) {
//        try {
//            return ResponseEntity.ok(consultationService.getActiveRoom(bookingId));
//        } catch (RuntimeException e) {
//            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(e.getMessage());
//        }
//    }
//
//    /**
//     * 4. CLINICAL DATA: Saves prescriptions to the record.
//     */
//    @PostMapping("/{id}/prescriptions")
//    @PreAuthorize("hasRole('DOCTOR')")
//    public ResponseEntity<String> savePrescriptions(
//            @PathVariable UUID id,
//            @RequestBody List<PrescriptionRequest> prescriptions
//    ) {
//        consultationService.savePrescriptions(id, prescriptions);
//        return ResponseEntity.ok("Prescriptions synchronized with patient vault.");
//    }
//
//    /**
//     * 5. SESSION WRAP-UP: Finalizes notes and releases slot.
//     */
//    @PatchMapping("/end/{id}")
//    @PreAuthorize("hasRole('DOCTOR')")
//    public ResponseEntity<String> end(@PathVariable UUID id, @RequestBody String notes) {
//        consultationService.endConsultation(id, notes);
//        return ResponseEntity.ok("Consultation archived and slot released.");
//    }
//
//    /**
//     * 6. CLINICAL HISTORY: View for Patient Dashboard.
//     */
//    @GetMapping("/patient/{patientId}")
//    @PreAuthorize("hasRole('PATIENT') or hasRole('ADMIN')")
//    public ResponseEntity<List<Consultation>> getHistory(@PathVariable UUID patientId) {
//        return ResponseEntity.ok(consultationService.getPatientConsultationHistory(patientId));
//    }
//}



package com.medibot.healthcare_platform.modules.consultation.controller;

import com.medibot.healthcare_platform.modules.consultation.dto.PrescriptionRequest;
import com.medibot.healthcare_platform.modules.consultation.dto.ConsultationEndRequest; // New DTO Import
import com.medibot.healthcare_platform.modules.consultation.entity.Consultation;
import com.medibot.healthcare_platform.modules.consultation.service.ConsultationService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/consultations")
@RequiredArgsConstructor
public class ConsultationController {
    private final ConsultationService consultationService;

    /**
     * 1. HANDSHAKE START: Initializes the clinical session record.
     * Accessible by both to ensure the context exists before Jitsi loads.
     */
    @PostMapping("/start/{bookingId}")
    @PreAuthorize("hasAnyRole('DOCTOR', 'PATIENT')")
    public ResponseEntity<Consultation> start(@PathVariable UUID bookingId) {
        return ResponseEntity.ok(consultationService.startConsultation(bookingId));
    }

    /**
     * 2. ROOM BROADCAST: Dr. Elena "stamps" the room ID.
     * Fixed: Consumes plain text to handle raw string inputs from Jitsi SDK.
     */
    @PatchMapping(value = "/{consultationId}/room", consumes = {"text/plain", "application/json"})
    @PreAuthorize("hasRole('DOCTOR')")
    public ResponseEntity<Void> updateRoomId(@PathVariable UUID consultationId, @RequestBody String roomId) {
        String cleanRoomId = roomId.replace("\"", ""); // Removes potential quotes
        consultationService.updateRoomId(consultationId, cleanRoomId);
        return ResponseEntity.ok().build();
    }

    /**
     * 3. ROOM DISCOVERY: Kartik finds Elena's authoritative room.
     */
    @GetMapping("/active/{bookingId}")
    @PreAuthorize("hasRole('PATIENT')")
    public ResponseEntity<String> getActiveRoom(@PathVariable UUID bookingId) {
        try {
            return ResponseEntity.ok(consultationService.getActiveRoom(bookingId));
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(e.getMessage());
        }
    }

    /**
     * 4. CLINICAL DATA: Saves medications to the live session.
     */
    @PostMapping("/{id}/prescriptions")
    @PreAuthorize("hasRole('DOCTOR')")
    public ResponseEntity<String> savePrescriptions(
            @PathVariable UUID id,
            @RequestBody List<PrescriptionRequest> prescriptions
    ) {
        consultationService.savePrescriptions(id, prescriptions);
        return ResponseEntity.ok("Prescriptions synchronized with patient vault.");
    }

    /**
     * 5. SESSION WRAP-UP: Finalizes notes and releases the slot.
     * FIX: Uses ConsultationEndRequest to avoid 'Body missing' errors.
     */
    @PatchMapping("/end/{id}")
    @PreAuthorize("hasRole('DOCTOR')")
    public ResponseEntity<String> end(
            @PathVariable UUID id,
            @RequestBody ConsultationEndRequest request
    ) {
        consultationService.endConsultation(id, request.getNotes());
        return ResponseEntity.ok("Consultation archived and slot released.");
    }

    /**
     * 6. CLINICAL HISTORY: View for Patient Dashboard.
     */
    @GetMapping("/patient/{patientId}")
    @PreAuthorize("hasRole('PATIENT') or hasRole('ADMIN')")
    public ResponseEntity<List<Consultation>> getHistory(@PathVariable UUID patientId) {
        return ResponseEntity.ok(consultationService.getPatientConsultationHistory(patientId));
    }
}