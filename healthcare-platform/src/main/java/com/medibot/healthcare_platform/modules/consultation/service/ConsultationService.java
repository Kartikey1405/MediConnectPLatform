//////////////////////package com.medibot.healthcare_platform.modules.consultation.service;
////////////////////////
////////////////////////import com.medibot.healthcare_platform.modules.consultation.entity.Consultation;
////////////////////////import com.medibot.healthcare_platform.modules.consultation.repository.ConsultationRepository;
////////////////////////import com.medibot.healthcare_platform.modules.booking.repository.BookingRepository;
////////////////////////import lombok.RequiredArgsConstructor;
////////////////////////import org.springframework.stereotype.Service;
////////////////////////import org.springframework.transaction.annotation.Transactional;
////////////////////////import java.time.LocalDateTime;
////////////////////////import java.util.UUID;
////////////////////////
////////////////////////@Service
////////////////////////@RequiredArgsConstructor
////////////////////////public class ConsultationService {
////////////////////////    private final ConsultationRepository consultationRepository;
////////////////////////    private final BookingRepository bookingRepository;
////////////////////////
////////////////////////    @Transactional
////////////////////////    public Consultation startConsultation(UUID bookingId) {
////////////////////////        var booking = bookingRepository.findById(bookingId).orElseThrow();
////////////////////////        Consultation consultation = Consultation.builder()
////////////////////////                .booking(booking)
////////////////////////                .startTime(LocalDateTime.now())
////////////////////////                .build();
////////////////////////        return consultationRepository.save(consultation);
////////////////////////    }
////////////////////////
////////////////////////    @Transactional
////////////////////////    public void endConsultation(UUID consultationId, String notes) {
////////////////////////        Consultation consultation = consultationRepository.findById(consultationId).orElseThrow();
////////////////////////        consultation.setEndTime(LocalDateTime.now());
////////////////////////        consultation.setDoctorNotes(notes);
////////////////////////        consultation.setCompleted(true);
////////////////////////        consultationRepository.save(consultation);
////////////////////////    }
////////////////////////}
//////////////////////
//////////////////////
//////////////////////
//////////////////////
//////////////////////
//////////////////////
//////////////////////package com.medibot.healthcare_platform.modules.consultation.service;
//////////////////////
//////////////////////import com.medibot.healthcare_platform.modules.consultation.entity.Consultation;
//////////////////////import com.medibot.healthcare_platform.modules.consultation.repository.ConsultationRepository;
//////////////////////import com.medibot.healthcare_platform.modules.booking.repository.BookingRepository;
//////////////////////import lombok.RequiredArgsConstructor;
//////////////////////import org.springframework.stereotype.Service;
//////////////////////import org.springframework.transaction.annotation.Transactional;
//////////////////////import java.time.LocalDateTime;
//////////////////////import java.util.List;
//////////////////////import java.util.UUID;
//////////////////////
//////////////////////@Service
//////////////////////@RequiredArgsConstructor
//////////////////////public class ConsultationService {
//////////////////////    private final ConsultationRepository consultationRepository;
//////////////////////    private final BookingRepository bookingRepository;
//////////////////////
//////////////////////    @Transactional
//////////////////////    public Consultation startConsultation(UUID bookingId) {
//////////////////////        var booking = bookingRepository.findById(bookingId).orElseThrow();
//////////////////////        Consultation consultation = Consultation.builder()
//////////////////////                .booking(booking)
//////////////////////                .startTime(LocalDateTime.now())
//////////////////////                .build();
//////////////////////        return consultationRepository.save(consultation);
//////////////////////    }
//////////////////////
//////////////////////    @Transactional
//////////////////////    public void endConsultation(UUID consultationId, String notes) {
//////////////////////        Consultation consultation = consultationRepository.findById(consultationId).orElseThrow();
//////////////////////        consultation.setEndTime(LocalDateTime.now());
//////////////////////        consultation.setDoctorNotes(notes);
//////////////////////        consultation.setCompleted(true);
//////////////////////        consultationRepository.save(consultation);
//////////////////////    }
//////////////////////
//////////////////////    /**
//////////////////////     * NEW: Fetch clinical history for the patient dashboard timeline.
//////////////////////     */
//////////////////////    public List<Consultation> getPatientConsultationHistory(UUID patientId) {
//////////////////////        return consultationRepository.findByBookingPatientIdAndIsCompletedTrueOrderByCreatedAtDesc(patientId);
//////////////////////    }
//////////////////////}
////////////////////
////////////////////
////////////////////
////////////////////
////////////////////
////////////////////
////////////////////
////////////////////
////////////////////package com.medibot.healthcare_platform.modules.consultation.service;
////////////////////
////////////////////import com.medibot.healthcare_platform.modules.consultation.entity.Consultation;
////////////////////import com.medibot.healthcare_platform.modules.consultation.repository.ConsultationRepository;
////////////////////import com.medibot.healthcare_platform.modules.booking.repository.BookingRepository;
////////////////////import com.medibot.healthcare_platform.modules.doctor.entity.SlotStatus;
////////////////////import com.medibot.healthcare_platform.modules.doctor.repository.SlotRepository;
////////////////////import lombok.RequiredArgsConstructor;
////////////////////import org.springframework.stereotype.Service;
////////////////////import org.springframework.transaction.annotation.Transactional;
////////////////////import java.time.LocalDateTime;
////////////////////import java.util.List;
////////////////////import java.util.UUID;
////////////////////
////////////////////@Service
////////////////////@RequiredArgsConstructor
////////////////////public class ConsultationService {
////////////////////    private final ConsultationRepository consultationRepository;
////////////////////    private final BookingRepository bookingRepository;
////////////////////    private final SlotRepository slotRepository; // NEW: Added to manage slot state
////////////////////
////////////////////    @Transactional
////////////////////    public Consultation startConsultation(UUID bookingId) {
////////////////////        var booking = bookingRepository.findById(bookingId).orElseThrow();
////////////////////        Consultation consultation = Consultation.builder()
////////////////////                .booking(booking)
////////////////////                .startTime(LocalDateTime.now())
////////////////////                .build();
////////////////////        return consultationRepository.save(consultation);
////////////////////    }
////////////////////
////////////////////    /**
////////////////////     * Finalizes the consultation and releases the slot for future bookings.
////////////////////     */
////////////////////    @Transactional
////////////////////    public void endConsultation(UUID consultationId, String notes) {
////////////////////        Consultation consultation = consultationRepository.findById(consultationId)
////////////////////                .orElseThrow(() -> new RuntimeException("Consultation not found"));
////////////////////
////////////////////        consultation.setEndTime(LocalDateTime.now());
////////////////////        consultation.setDoctorNotes(notes);
////////////////////        consultation.setCompleted(true);
////////////////////
////////////////////        // RELEASE LOGIC: Reset slot to AVAILABLE so it reappears on the patient side
////////////////////        var slot = consultation.getBooking().getSlot();
////////////////////        slot.setStatus(SlotStatus.AVAILABLE);
////////////////////        slotRepository.save(slot);
////////////////////
////////////////////        consultationRepository.save(consultation);
////////////////////    }
////////////////////
////////////////////    public List<Consultation> getPatientConsultationHistory(UUID patientId) {
////////////////////        return consultationRepository.findByBookingPatientIdAndIsCompletedTrueOrderByCreatedAtDesc(patientId);
////////////////////    }
////////////////////}
//////////////////
//////////////////
//////////////////package com.medibot.healthcare_platform.modules.consultation.service;
//////////////////
//////////////////import com.medibot.healthcare_platform.modules.consultation.entity.Consultation;
//////////////////import com.medibot.healthcare_platform.modules.consultation.repository.ConsultationRepository;
//////////////////import com.medibot.healthcare_platform.modules.booking.repository.BookingRepository;
//////////////////import com.medibot.healthcare_platform.modules.doctor.entity.SlotStatus;
//////////////////import com.medibot.healthcare_platform.modules.doctor.repository.SlotRepository;
//////////////////import lombok.RequiredArgsConstructor;
//////////////////import org.springframework.stereotype.Service;
//////////////////import org.springframework.transaction.annotation.Transactional;
//////////////////
//////////////////import java.time.LocalDateTime;
//////////////////import java.util.List;
//////////////////import java.util.UUID;
//////////////////
//////////////////@Service
//////////////////@RequiredArgsConstructor
//////////////////public class ConsultationService {
//////////////////    private final ConsultationRepository consultationRepository;
//////////////////    private final BookingRepository bookingRepository;
//////////////////    private final SlotRepository slotRepository;
//////////////////
//////////////////    /**
//////////////////     * START SESSION: Checks if session exists first to prevent 500 error.
//////////////////     */
//////////////////    @Transactional
//////////////////    public Consultation startConsultation(UUID bookingId) {
//////////////////        // 1. Check if a session already exists for this booking
//////////////////        return consultationRepository.findByBookingId(bookingId)
//////////////////                .orElseGet(() -> {
//////////////////                    // 2. If not, create a new one
//////////////////                    var booking = bookingRepository.findById(bookingId)
//////////////////                            .orElseThrow(() -> new RuntimeException("Booking reference not found"));
//////////////////
//////////////////                    Consultation consultation = Consultation.builder()
//////////////////                            .booking(booking)
//////////////////                            .startTime(LocalDateTime.now())
//////////////////                            .isCompleted(false)
//////////////////                            .build();
//////////////////                    return consultationRepository.save(consultation);
//////////////////                });
//////////////////    }
//////////////////
//////////////////    /**
//////////////////     * END SESSION: Finalizes record and releases the slot for reuse.
//////////////////     */
//////////////////    @Transactional
//////////////////    public void endConsultation(UUID consultationId, String notes) {
//////////////////        Consultation consultation = consultationRepository.findById(consultationId)
//////////////////                .orElseThrow(() -> new RuntimeException("Consultation not found"));
//////////////////
//////////////////        consultation.setEndTime(LocalDateTime.now());
//////////////////        consultation.setDoctorNotes(notes);
//////////////////        consultation.setCompleted(true);
//////////////////
//////////////////        // RELEASE LOGIC: mark slot as AVAILABLE again
//////////////////        var slot = consultation.getBooking().getSlot();
//////////////////        slot.setStatus(SlotStatus.AVAILABLE);
//////////////////        slotRepository.save(slot);
//////////////////
//////////////////        consultationRepository.save(consultation);
//////////////////    }
//////////////////
//////////////////    public List<Consultation> getPatientConsultationHistory(UUID patientId) {
//////////////////        return consultationRepository.findByBookingPatientIdAndIsCompletedTrueOrderByCreatedAtDesc(patientId);
//////////////////    }
//////////////////}
////////////////
////////////////
////////////////package com.medibot.healthcare_platform.modules.consultation.service;
////////////////
////////////////import com.medibot.healthcare_platform.modules.consultation.entity.Consultation;
////////////////import com.medibot.healthcare_platform.modules.consultation.repository.ConsultationRepository;
////////////////import com.medibot.healthcare_platform.modules.booking.repository.BookingRepository;
////////////////import com.medibot.healthcare_platform.modules.doctor.entity.SlotStatus;
////////////////import com.medibot.healthcare_platform.modules.doctor.repository.SlotRepository;
////////////////import lombok.RequiredArgsConstructor;
////////////////import org.springframework.stereotype.Service;
////////////////import org.springframework.transaction.annotation.Transactional;
////////////////
////////////////import java.time.LocalDateTime;
////////////////import java.util.List;
////////////////import java.util.UUID;
////////////////
////////////////@Service
////////////////@RequiredArgsConstructor
////////////////public class ConsultationService {
////////////////    private final ConsultationRepository consultationRepository;
////////////////    private final BookingRepository bookingRepository;
////////////////    private final SlotRepository slotRepository;
////////////////
////////////////    /**
////////////////     * START SESSION:
////////////////     * Idempotent logic to prevent 500 errors when multiple users join the same room.
////////////////     */
////////////////    @Transactional
////////////////    public Consultation startConsultation(UUID bookingId) {
////////////////        // 1. Check if a session already exists for this booking ID to avoid Unique Constraint violations
////////////////        return consultationRepository.findByBookingId(bookingId)
////////////////                .orElseGet(() -> {
////////////////                    // 2. If no session exists, find the booking and initialize a new clinical record
////////////////                    var booking = bookingRepository.findById(bookingId)
////////////////                            .orElseThrow(() -> new RuntimeException("Booking reference not found: " + bookingId));
////////////////
////////////////                    Consultation consultation = Consultation.builder()
////////////////                            .booking(booking)
////////////////                            .startTime(LocalDateTime.now())
////////////////                            .isCompleted(false)
////////////////                            .build();
////////////////                    return consultationRepository.save(consultation);
////////////////                });
////////////////    }
////////////////
////////////////    /**
////////////////     * END SESSION:
////////////////     * Finalizes the medical record and releases the slot status back to AVAILABLE.
////////////////     */
////////////////    @Transactional
////////////////    public void endConsultation(UUID consultationId, String notes) {
////////////////        Consultation consultation = consultationRepository.findById(consultationId)
////////////////                .orElseThrow(() -> new RuntimeException("Consultation session not found: " + consultationId));
////////////////
////////////////        consultation.setEndTime(LocalDateTime.now());
////////////////        consultation.setDoctorNotes(notes);
////////////////        consultation.setCompleted(true);
////////////////
////////////////        // RELEASE LOGIC: mark the slot as bookable again on the patient dashboard
////////////////        if (consultation.getBooking() != null && consultation.getBooking().getSlot() != null) {
////////////////            var slot = consultation.getBooking().getSlot();
////////////////            slot.setStatus(SlotStatus.AVAILABLE);
////////////////            slotRepository.save(slot);
////////////////        }
////////////////
////////////////        consultationRepository.save(consultation);
////////////////    }
////////////////
////////////////    /**
////////////////     * HISTORY: Fetches all verified records for the patient timeline.
////////////////     */
////////////////    public List<Consultation> getPatientConsultationHistory(UUID patientId) {
////////////////        return consultationRepository.findByBookingPatientIdAndIsCompletedTrueOrderByCreatedAtDesc(patientId);
////////////////    }
////////////////}
//////////////
//////////////
//////////////
//////////////
//////////////package com.medibot.healthcare_platform.modules.consultation.service;
//////////////
//////////////import com.medibot.healthcare_platform.modules.consultation.entity.Consultation;
//////////////import com.medibot.healthcare_platform.modules.consultation.repository.ConsultationRepository;
//////////////import com.medibot.healthcare_platform.modules.booking.repository.BookingRepository;
//////////////import com.medibot.healthcare_platform.modules.doctor.entity.SlotStatus;
//////////////import com.medibot.healthcare_platform.modules.doctor.repository.SlotRepository;
//////////////import lombok.RequiredArgsConstructor;
//////////////import org.springframework.stereotype.Service;
//////////////import org.springframework.transaction.annotation.Transactional;
//////////////
//////////////import java.time.LocalDateTime;
//////////////import java.util.List;
//////////////import java.util.UUID;
//////////////
//////////////@Service
//////////////@RequiredArgsConstructor
//////////////public class ConsultationService {
//////////////    private final ConsultationRepository consultationRepository;
//////////////    private final BookingRepository bookingRepository;
//////////////    private final SlotRepository slotRepository;
//////////////
//////////////    /**
//////////////     * START SESSION:
//////////////     * Logic corrected to be idempotent. This prevents 500 errors when Dr. Elena
//////////////     * and Kartik join the same room or refresh their browsers.
//////////////     */
//////////////    @Transactional
//////////////    public Consultation startConsultation(UUID bookingId) {
//////////////        // 1. Check if a clinical session already exists for this booking ID
//////////////        // This avoids the 'duplicate key value violates unique constraint' error
//////////////        return consultationRepository.findByBookingId(bookingId)
//////////////                .orElseGet(() -> {
//////////////                    // 2. If no session exists, initialize a new medical record link
//////////////                    var booking = bookingRepository.findById(bookingId)
//////////////                            .orElseThrow(() -> new RuntimeException("Booking reference not found: " + bookingId));
//////////////
//////////////                    Consultation consultation = Consultation.builder()
//////////////                            .booking(booking)
//////////////                            .startTime(LocalDateTime.now())
//////////////                            .isCompleted(false)
//////////////                            .build();
//////////////                    return consultationRepository.save(consultation);
//////////////                });
//////////////    }
//////////////
//////////////    /**
//////////////     * END SESSION:
//////////////     * Finalizes the doctor's clinical notes and releases the slot for the next patient.
//////////////     */
//////////////    @Transactional
//////////////    public void endConsultation(UUID consultationId, String notes) {
//////////////        Consultation consultation = consultationRepository.findById(consultationId)
//////////////                .orElseThrow(() -> new RuntimeException("Consultation session not found: " + consultationId));
//////////////
//////////////        consultation.setEndTime(LocalDateTime.now());
//////////////        consultation.setDoctorNotes(notes);
//////////////        consultation.setCompleted(true);
//////////////
//////////////        // RELEASE LOGIC: mark the slot as AVAILABLE so it reappears for booking
//////////////        if (consultation.getBooking() != null && consultation.getBooking().getSlot() != null) {
//////////////            var slot = consultation.getBooking().getSlot();
//////////////            slot.setStatus(SlotStatus.AVAILABLE);
//////////////            slotRepository.save(slot);
//////////////        }
//////////////
//////////////        consultationRepository.save(consultation);
//////////////    }
//////////////
//////////////    /**
//////////////     * HISTORY: Retrieves verified clinical records for the Patient timeline.
//////////////     */
//////////////    public List<Consultation> getPatientConsultationHistory(UUID patientId) {
//////////////        return consultationRepository.findByBookingPatientIdAndIsCompletedTrueOrderByCreatedAtDesc(patientId);
//////////////    }
//////////////}
////////////
////////////
////////////
////////////
////////////package com.medibot.healthcare_platform.modules.consultation.service;
////////////
////////////import com.medibot.healthcare_platform.modules.consultation.entity.Consultation;
////////////import com.medibot.healthcare_platform.modules.consultation.repository.ConsultationRepository;
////////////import com.medibot.healthcare_platform.modules.booking.repository.BookingRepository;
////////////import com.medibot.healthcare_platform.modules.doctor.entity.SlotStatus;
////////////import com.medibot.healthcare_platform.modules.doctor.repository.SlotRepository;
////////////import lombok.RequiredArgsConstructor;
////////////import org.springframework.stereotype.Service;
////////////import org.springframework.transaction.annotation.Transactional;
////////////
////////////import java.time.LocalDateTime;
////////////import java.util.List;
////////////import java.util.UUID;
////////////
////////////@Service
////////////@RequiredArgsConstructor
////////////public class ConsultationService {
////////////    private final ConsultationRepository consultationRepository;
////////////    private final BookingRepository bookingRepository;
////////////    private final SlotRepository slotRepository;
////////////
////////////    @Transactional
////////////    public Consultation startConsultation(UUID bookingId) {
////////////        // 1. First, check if Elena or Kartik already started this session
////////////        return consultationRepository.findByBookingId(bookingId)
////////////                .orElseGet(() -> {
////////////                    // 2. Only if no session exists, create the record
////////////                    var booking = bookingRepository.findById(bookingId)
////////////                            .orElseThrow(() -> new RuntimeException("Booking not found"));
////////////
////////////                    Consultation consultation = Consultation.builder()
////////////                            .booking(booking)
////////////                            .startTime(LocalDateTime.now())
////////////                            .isCompleted(false)
////////////                            .build();
////////////                    return consultationRepository.save(consultation);
////////////                });
////////////    }
////////////    /**
////////////     * END SESSION:
////////////     * Finalizes clinical documentation and automatically releases the slot.
////////////     */
////////////    @Transactional
////////////    public void endConsultation(UUID consultationId, String notes) {
////////////        Consultation consultation = consultationRepository.findById(consultationId)
////////////                .orElseThrow(() -> new RuntimeException("Clinical session ID not found: " + consultationId));
////////////
////////////        consultation.setEndTime(LocalDateTime.now());
////////////        consultation.setDoctorNotes(notes);
////////////        consultation.setCompleted(true);
////////////
////////////        // RELEASE LOGIC: Automatically "un-fills" the slot so it can be re-booked
////////////        if (consultation.getBooking() != null && consultation.getBooking().getSlot() != null) {
////////////            var slot = consultation.getBooking().getSlot();
////////////            slot.setStatus(SlotStatus.AVAILABLE);
////////////            slotRepository.save(slot);
////////////        }
////////////
////////////        consultationRepository.save(consultation);
////////////    }
////////////
////////////    /**
////////////     * CLINICAL HISTORY:
////////////     * Traverses relationships to fetch all completed records for the patient timeline.
////////////     */
////////////    public List<Consultation> getPatientConsultationHistory(UUID patientId) {
////////////        return consultationRepository.findByBookingPatientIdAndIsCompletedTrueOrderByCreatedAtDesc(patientId);
////////////    }
////////////
////////////    public void updateRoomId(UUID id, String roomId) {
////////////        Consultation c = consultationRepository.findById(id).orElseThrow();
////////////        c.setRoomId(roomId); // You'll need to add this field to your Consultation entity
////////////        consultationRepository.save(c);
////////////    }
////////////
////////////    public String getRoomIdByBooking(UUID bookingId) {
////////////        return consultationRepository.findByBookingId(bookingId)
////////////                .map(Consultation::getRoomId)
////////////                .orElseThrow(() -> new RuntimeException("Doctor has not joined yet"));
////////////    }
////////////}
//////////
//////////
//////////
//////////package com.medibot.healthcare_platform.modules.consultation.service;
//////////
//////////import com.medibot.healthcare_platform.modules.consultation.entity.Consultation;
//////////import com.medibot.healthcare_platform.modules.consultation.repository.ConsultationRepository;
//////////import com.medibot.healthcare_platform.modules.booking.repository.BookingRepository;
//////////import com.medibot.healthcare_platform.modules.doctor.entity.SlotStatus;
//////////import com.medibot.healthcare_platform.modules.doctor.repository.SlotRepository;
//////////import lombok.RequiredArgsConstructor;
//////////import org.springframework.http.HttpStatus;
//////////import org.springframework.http.ResponseEntity;
//////////import org.springframework.security.access.prepost.PreAuthorize;
//////////import org.springframework.stereotype.Service;
//////////import org.springframework.transaction.annotation.Transactional;
//////////import org.springframework.web.bind.annotation.*;
//////////
//////////import java.time.LocalDateTime;
//////////import java.util.List;
//////////import java.util.UUID;
//////////
//////////@Service
//////////@RequiredArgsConstructor
//////////public class ConsultationService {
//////////    private final ConsultationRepository consultationRepository;
//////////    private final BookingRepository bookingRepository;
//////////    private final SlotRepository slotRepository;
//////////
//////////    /**
//////////     * IDEMPOTENT START: Returns the existing session or creates one.
//////////     * Prevents the 500 error you saw in the logs.
//////////     */
//////////    @Transactional
//////////    public Consultation startConsultation(UUID bookingId) {
//////////        return consultationRepository.findByBookingId(bookingId)
//////////                .orElseGet(() -> {
//////////                    var booking = bookingRepository.findById(bookingId)
//////////                            .orElseThrow(() -> new RuntimeException("Booking reference not found: " + bookingId));
//////////
//////////                    Consultation consultation = Consultation.builder()
//////////                            .booking(booking)
//////////                            .startTime(LocalDateTime.now())
//////////                            .isCompleted(false)
//////////                            .build();
//////////                    return consultationRepository.save(consultation);
//////////                });
//////////    }
//////////
//////////    /**
//////////     * ROOM HANDSHAKE: Sets the authoritative Jitsi room created by the Doctor.
//////////     */
//////////    @Transactional
//////////    public void updateRoomId(UUID id, String roomId) {
//////////        Consultation c = consultationRepository.findById(id)
//////////                .orElseThrow(() -> new RuntimeException("Consultation session not found: " + id));
//////////        c.setRoomId(roomId);
//////////        consultationRepository.save(c);
//////////    }
//////////
//////////    /**
//////////     * ROOM DISCOVERY: Allows Kartik to find Elena's room without "guessing".
//////////     */
//////////    @Transactional(readOnly = true)
//////////    public String getRoomIdByBooking(UUID bookingId) {
//////////        return consultationRepository.findByBookingId(bookingId)
//////////                .map(Consultation::getRoomId)
//////////                .filter(roomId -> roomId != null && !roomId.isEmpty())
//////////                .orElseThrow(() -> new RuntimeException("Doctor has not initialized the room yet."));
//////////    }
//////////
//////////    /**
//////////     * END SESSION: Finalizes record and releases the slot to AVAILABLE.
//////////     */
//////////    @Transactional
//////////    public void endConsultation(UUID consultationId, String notes) {
//////////        Consultation consultation = consultationRepository.findById(consultationId)
//////////                .orElseThrow(() -> new RuntimeException("Clinical record archive failed: ID not found"));
//////////
//////////        consultation.setEndTime(LocalDateTime.now());
//////////        consultation.setDoctorNotes(notes);
//////////        consultation.setCompleted(true);
//////////
//////////        // RELEASE LOGIC: un-fill the slot automatically
//////////        if (consultation.getBooking() != null && consultation.getBooking().getSlot() != null) {
//////////            var slot = consultation.getBooking().getSlot();
//////////            slot.setStatus(SlotStatus.AVAILABLE);
//////////            slotRepository.save(slot);
//////////        }
//////////
//////////        consultationRepository.save(consultation);
//////////    }
//////////
//////////    /**
//////////     * HISTORY: Fetches all verified records for the patient timeline.
//////////     */
//////////    public List<Consultation> getPatientConsultationHistory(UUID patientId) {
//////////        return consultationRepository.findByBookingPatientIdAndIsCompletedTrueOrderByCreatedAtDesc(patientId);
//////////    }
//////////
//////////    ////package com.medibot.healthcare_platform.modules.consultation.controller;
//////////    ////
//////////    ////import com.medibot.healthcare_platform.modules.consultation.entity.Consultation;
//////////    ////import com.medibot.healthcare_platform.modules.consultation.service.ConsultationService;
//////////    ////import lombok.RequiredArgsConstructor;
//////////    ////import org.springframework.http.ResponseEntity;
//////////    ////import org.springframework.security.access.prepost.PreAuthorize;
//////////    ////import org.springframework.web.bind.annotation.*;
//////////    ////import java.util.UUID;
//////////    ////
//////////    ////@RestController
//////////    ////@RequestMapping("/api/consultations")
//////////    ////@RequiredArgsConstructor
//////////    ////public class ConsultationController {
//////////    ////    private final ConsultationService consultationService;
//////////    ////
//////////    ////    @PostMapping("/start/{bookingId}")
//////////    ////    @PreAuthorize("hasRole('DOCTOR')")
//////////    ////    public ResponseEntity<Consultation> start(@PathVariable UUID bookingId) {
//////////    ////        return ResponseEntity.ok(consultationService.startConsultation(bookingId));
//////////    ////    }
//////////    ////
//////////    ////    @PatchMapping("/end/{id}")
//////////    ////    @PreAuthorize("hasRole('DOCTOR')")
//////////    ////    public ResponseEntity<String> end(@PathVariable UUID id, @RequestBody String notes) {
//////////    ////        consultationService.endConsultation(id, notes);
//////////    ////        return ResponseEntity.ok("Consultation ended and notes saved.");
//////////    ////    }
//////////    ////}
////////////
////////////
////////////
////////////
////////////package com.medibot.healthcare_platform.modules.consultation.controller;
////////////
////////////import com.medibot.healthcare_platform.modules.consultation.entity.Consultation;
////////////import com.medibot.healthcare_platform.modules.consultation.service.ConsultationService;
////////////import lombok.RequiredArgsConstructor;
////////////import org.springframework.http.ResponseEntity;
////////////import org.springframework.security.access.prepost.PreAuthorize;
////////////import org.springframework.web.bind.annotation.*;
////////////import java.util.List;
////////////import java.util.UUID;
////////////
////////////@RestController
////////////@RequestMapping("/api/consultations")
////////////@RequiredArgsConstructor
////////////public class ConsultationController {
////////////    private final ConsultationService consultationService;
////////////
////////////    @PostMapping("/start/{bookingId}")
////////////    @PreAuthorize("hasRole('DOCTOR')")
////////////    public ResponseEntity<Consultation> start(@PathVariable UUID bookingId) {
////////////        return ResponseEntity.ok(consultationService.startConsultation(bookingId));
////////////    }
////////////
////////////    @PatchMapping("/end/{id}")
////////////    @PreAuthorize("hasRole('DOCTOR')")
////////////    public ResponseEntity<String> end(@PathVariable UUID id, @RequestBody String notes) {
////////////        consultationService.endConsultation(id, notes);
////////////        return ResponseEntity.ok("Consultation ended and notes saved.");
////////////    }
////////////
////////////    /**
////////////     * NEW: Endpoint for Patients to view their verified medical notes.
////////////     */
////////////    @GetMapping("/patient/{patientId}")
////////////    @PreAuthorize("hasRole('PATIENT') or hasRole('ADMIN')")
////////////    public ResponseEntity<List<Consultation>> getHistory(@PathVariable UUID patientId) {
////////////        return ResponseEntity.ok(consultationService.getPatientConsultationHistory(patientId));
////////////    }
////////////
////////////    // Allows the doctor to "broadcast" the room ID they just joined
////////////    @PatchMapping("/{consultationId}/room/{roomId}")
////////////    public ResponseEntity<?> updateRoomId(@PathVariable UUID consultationId, @PathVariable String roomId) {
////////////        consultationService.updateRoomId(consultationId, roomId);
////////////        return ResponseEntity.ok().build();
////////////    }
////////////
////////////    // Allows the patient to "discover" which room the doctor is in
////////////    @GetMapping("/active/{bookingId}")
////////////    public ResponseEntity<String> getActiveRoom(@PathVariable UUID bookingId) {
////////////        return ResponseEntity.ok(consultationService.getRoomIdByBooking(bookingId));
////////////    }
////////////}
//////////
//////////package com.medibot.healthcare_platform.modules.consultation.controller;
//////////
//////////import com.medibot.healthcare_platform.modules.consultation.entity.Consultation;
//////////import com.medibot.healthcare_platform.modules.consultation.service.ConsultationService;
//////////import jakarta.transaction.Transactional;
//////////import lombok.RequiredArgsConstructor;
//////////import org.springframework.http.HttpStatus;
//////////import org.springframework.http.ResponseEntity;
//////////import org.springframework.security.access.prepost.PreAuthorize;
//////////import org.springframework.web.bind.annotation.*;
//////////
//////////import java.util.List;
//////////import java.util.UUID;
//////////
//////////    @RestController
//////////    @RequestMapping("/api/consultations")
//////////    @RequiredArgsConstructor
//////////    public class ConsultationController {
//////////        private final ConsultationService consultationService;
//////////
//////////        /**
//////////         * HANDSHAKE START:
//////////         * Used by both Doctor and Patient to enter the context of the call.
//////////         */
//////////        @PostMapping("/start/{bookingId}")
//////////        @PreAuthorize("hasAnyRole('DOCTOR', 'PATIENT')")
//////////        public ResponseEntity<Consultation> start(@PathVariable UUID bookingId) {
//////////            return ResponseEntity.ok(consultationService.startConsultation(bookingId));
//////////        }
//////////
//////////        /**
//////////         * ROOM BROADCAST:
//////////         * Dr. Elena calls this to "pin" the authoritative Jitsi Room ID to the database.
//////////         */
//////////        @PatchMapping("/{consultationId}/room")
//////////        @PreAuthorize("hasRole('DOCTOR')")
//////////        public ResponseEntity<Void> updateRoomId(@PathVariable UUID consultationId, @RequestBody String roomId) {
//////////            consultationService.updateRoomId(consultationId, roomId);
//////////            return ResponseEntity.ok().build();
//////////        }
//////////
//////////        /**
//////////         * ROOM DISCOVERY:
//////////         * Kartik calls this to find exactly which room Elena has created.
//////////         */
//////////        @GetMapping("/active/{bookingId}")
//////////        @PreAuthorize("hasRole('PATIENT')")
//////////        public ResponseEntity<String> getActiveRoom(@PathVariable UUID bookingId) {
//////////            try {
//////////                return ResponseEntity.ok(consultationService.getRoomIdByBooking(bookingId));
//////////            } catch (RuntimeException e) {
//////////                return ResponseEntity.status(HttpStatus.NOT_FOUND).body(e.getMessage());
//////////            }
//////////        }
//////////
//////////        /**
//////////         * WRAP-UP:
//////////         * Finalizes the notes and triggers the slot release.
//////////         */
//////////        @PatchMapping("/end/{id}")
//////////        @PreAuthorize("hasRole('DOCTOR')")
//////////        public ResponseEntity<String> end(@PathVariable UUID id, @RequestBody String notes) {
//////////            consultationService.endConsultation(id, notes);
//////////            return ResponseEntity.ok("Consultation archived and slot released.");
//////////        }
//////////
//////////        /**
//////////         * HISTORY:
//////////         * Used by the Patient Dashboard to show the Medical Records library.
//////////         */
//////////        @GetMapping("/patient/{patientId}")
//////////        @PreAuthorize("hasRole('PATIENT') or hasRole('ADMIN')")
//////////        public ResponseEntity<List<Consultation>> getHistory(@PathVariable UUID patientId) {
//////////            return ResponseEntity.ok(consultationService.getPatientConsultationHistory(patientId));
//////////        }
//////////
//////////        // Inside your updateRoomId method in ConsultationService.java
//////////        @jakarta.transaction.Transactional
//////////        public void updateRoomId(UUID id, String roomId) {
//////////            Consultation c = consultationRepository.findById(id).orElseThrow();
//////////            c.setRoomId(roomId);
//////////            consultationRepository.save(c);
//////////
//////////            // TRIGGER NOTIFICATION
//////////            String joinLink = "/patient/consultation/" + c.getBooking().getId();
//////////            notificationService.createNotification(
//////////                    c.getBooking().getPatient().getId(),
//////////                    "Dr. " + c.getBooking().getSlot().getDoctor().getUser().getFirstName() + " has joined the room. Click to enter.",
//////////                    "CONSULTATION_STARTED",
//////////                    joinLink
//////////            );
//////////        }
//////////    }
//////////}
////////
////////
////////package com.medibot.healthcare_platform.modules.consultation.service;
////////
////////import com.medibot.healthcare_platform.modules.consultation.entity.Consultation;
////////import com.medibot.healthcare_platform.modules.consultation.repository.ConsultationRepository;
////////import com.medibot.healthcare_platform.modules.booking.repository.BookingRepository;
////////import com.medibot.healthcare_platform.modules.doctor.entity.SlotStatus;
////////import com.medibot.healthcare_platform.modules.doctor.repository.SlotRepository;
////////import com.medibot.healthcare_platform.modules.notification.service.NotificationService; // Use your new module
////////import lombok.RequiredArgsConstructor;
////////import org.springframework.stereotype.Service;
////////import org.springframework.transaction.annotation.Transactional;
////////
////////import java.time.LocalDateTime;
////////import java.util.List;
////////import java.util.UUID;
////////
////////@Service
////////@RequiredArgsConstructor
////////public class ConsultationService {
////////    private final ConsultationRepository consultationRepository;
////////    private final BookingRepository bookingRepository;
////////    private final SlotRepository slotRepository;
////////    private final NotificationService notificationService;
////////
////////    @Transactional
////////    public Consultation startConsultation(UUID bookingId) {
////////        return consultationRepository.findByBookingId(bookingId)
////////                .orElseGet(() -> {
////////                    var booking = bookingRepository.findById(bookingId)
////////                            .orElseThrow(() -> new RuntimeException("Booking reference not found"));
////////
////////                    Consultation consultation = Consultation.builder()
////////                            .booking(booking)
////////                            .startTime(LocalDateTime.now())
////////                            .isCompleted(false)
////////                            .build();
////////                    return consultationRepository.save(consultation);
////////                });
////////    }
////////
////////    /**
////////     * THE HANDSHAKE: Sets room ID and alerts the patient.
////////     */
////////    @Transactional
////////    public void updateRoomId(UUID id, String roomId) {
////////        Consultation c = consultationRepository.findById(id)
////////                .orElseThrow(() -> new RuntimeException("Consultation not found"));
////////
////////        c.setRoomId(roomId);
////////        consultationRepository.save(c);
////////
////////        // TRIGGER NOTIFICATION: Kartik gets an alert when Elena joins
////////        String joinLink = "/patient/consultation/" + c.getBooking().getId();
////////        notificationService.createNotification(
////////                c.getBooking().getPatient().getId(),
////////                "Dr. " + c.getBooking().getSlot().getDoctor().getUser().getFirstName() + " has joined the room. Click to enter.",
////////                "CONSULTATION_STARTED",
////////                joinLink
////////        );
////////    }
////////
////////    @Transactional(readOnly = true)
////////    public String getRoomIdByBooking(UUID bookingId) {
////////        return consultationRepository.findByBookingId(bookingId)
////////                .map(Consultation::getRoomId)
////////                .filter(room -> room != null && !room.isEmpty())
////////                .orElseThrow(() -> new RuntimeException("Doctor has not initialized the room yet."));
////////    }
////////
////////    @Transactional
////////    public void endConsultation(UUID consultationId, String notes) {
////////        Consultation c = consultationRepository.findById(consultationId).orElseThrow();
////////        c.setEndTime(LocalDateTime.now());
////////        c.setDoctorNotes(notes);
////////        c.setCompleted(true);
////////
////////        if (c.getBooking() != null && c.getBooking().getSlot() != null) {
////////            var slot = c.getBooking().getSlot();
////////            slot.setStatus(SlotStatus.AVAILABLE);
////////            slotRepository.save(slot);
////////        }
////////        consultationRepository.save(c);
////////    }
////////
////////    public List<Consultation> getPatientConsultationHistory(UUID patientId) {
////////        return consultationRepository.findByBookingPatientIdAndIsCompletedTrueOrderByCreatedAtDesc(patientId);
////////    }
////////
////////    @Transactional
////////    public void savePrescriptions(UUID consultationId, List<PrescriptionRequest> requests) {
////////        Consultation consultation = consultationRepository.findById(consultationId)
////////                .orElseThrow(() -> new RuntimeException("Consultation not found"));
////////
////////        List<Prescription> prescriptions = requests.stream().map(req ->
////////                Prescription.builder()
////////                        .consultation(consultation)
////////                        .medicineName(req.getMedicineName())
////////                        .dosage(req.getDosage())
////////                        .frequency(req.getFrequency())
////////                        .duration(req.getDuration())
////////                        .instructions(req.getInstructions())
////////                        .build()
////////        ).toList();
////////
////////        // You will need a PrescriptionRepository to save these
////////        prescriptionRepository.saveAll(prescriptions);
////////    }
////////}
//////
//////
//////package com.medibot.healthcare_platform.modules.consultation.service;
//////
//////import com.medibot.healthcare_platform.modules.consultation.dto.PrescriptionRequest;
//////import com.medibot.healthcare_platform.modules.consultation.entity.Consultation;
//////import com.medibot.healthcare_platform.modules.consultation.entity.Prescription;
//////import com.medibot.healthcare_platform.modules.consultation.repository.ConsultationRepository;
//////import com.medibot.healthcare_platform.modules.consultation.repository.PrescriptionRepository;
//////import com.medibot.healthcare_platform.modules.booking.repository.BookingRepository;
//////import com.medibot.healthcare_platform.modules.doctor.entity.SlotStatus;
//////import com.medibot.healthcare_platform.modules.doctor.repository.SlotRepository;
//////import com.medibot.healthcare_platform.modules.notification.service.NotificationService;
//////import lombok.RequiredArgsConstructor;
//////import org.springframework.stereotype.Service;
//////import org.springframework.transaction.annotation.Transactional;
//////
//////import java.time.LocalDateTime;
//////import java.util.List;
//////import java.util.UUID;
//////
//////@Service
//////@RequiredArgsConstructor
//////public class ConsultationService {
//////
//////    private final ConsultationRepository consultationRepository;
//////    private final BookingRepository bookingRepository;
//////    private final SlotRepository slotRepository;
//////    private final NotificationService notificationService;
//////    private final PrescriptionRepository prescriptionRepository;
//////
//////    /**
//////     * START SESSION:
//////     * Idempotent check ensures Elena and Kartik don't create two separate sessions.
//////     */
//////    @Transactional
//////    public Consultation startConsultation(UUID bookingId) {
//////        return consultationRepository.findByBookingId(bookingId)
//////                .orElseGet(() -> {
//////                    var booking = bookingRepository.findById(bookingId)
//////                            .orElseThrow(() -> new RuntimeException("Booking reference not found: " + bookingId));
//////
//////                    Consultation consultation = Consultation.builder()
//////                            .booking(booking)
//////                            .startTime(LocalDateTime.now())
//////                            .isCompleted(false)
//////                            .build();
//////                    return consultationRepository.save(consultation);
//////                });
//////    }
//////
//////    /**
//////     * THE HANDSHAKE: Sets Room ID and triggers real-time alert for Patient.
//////     */
//////    @Transactional
//////    public void updateRoomId(UUID id, String roomId) {
//////        Consultation c = consultationRepository.findById(id)
//////                .orElseThrow(() -> new RuntimeException("Consultation not found"));
//////
//////        c.setRoomId(roomId);
//////        consultationRepository.save(c);
//////
//////        // NOTIFICATION: Trigger persistent alert for Kartik to join Elena
//////        String joinLink = "/patient/consultation/" + c.getBooking().getId();
//////        notificationService.createNotification(
//////                c.getBooking().getPatient().getId(),
//////                "Dr. " + c.getBooking().getSlot().getDoctor().getUser().getFirstName() + " has initialized your video room. Click to join.",
//////                "CONSULTATION_STARTED",
//////                joinLink
//////        );
//////    }
//////
//////    /**
//////     * DISCOVERY: Allows Kartik's browser to find exactly where Elena is.
//////     */
//////    @Transactional(readOnly = true)
//////    public String getRoomIdByBooking(UUID bookingId) {
//////        return consultationRepository.findByBookingId(bookingId)
//////                .map(Consultation::getRoomId)
//////                .filter(room -> room != null && !room.isEmpty())
//////                .orElseThrow(() -> new RuntimeException("Doctor is preparing the clinical room. Please wait."));
//////    }
//////
//////    /**
//////     * END SESSION: Finalizes the record and resets the doctor's slot to AVAILABLE.
//////     */
//////    @Transactional
//////    public void endConsultation(UUID consultationId, String notes) {
//////        Consultation c = consultationRepository.findById(consultationId)
//////                .orElseThrow(() -> new RuntimeException("Consultation ID not found"));
//////
//////        c.setEndTime(LocalDateTime.now());
//////        c.setDoctorNotes(notes);
//////        c.setCompleted(true);
//////
//////        // RELEASE SLOT: Make the time slot bookable again on the platform
//////        if (c.getBooking() != null && c.getBooking().getSlot() != null) {
//////            var slot = c.getBooking().getSlot();
//////            slot.setStatus(SlotStatus.AVAILABLE);
//////            slotRepository.save(slot);
//////        }
//////        consultationRepository.save(c);
//////    }
//////
//////    /**
//////     * HISTORY: Fetches all verified medical history for the patient timeline.
//////     */
//////    public List<Consultation> getPatientConsultationHistory(UUID patientId) {
//////        return consultationRepository.findByBookingPatientIdAndIsCompletedTrueOrderByCreatedAtDesc(patientId);
//////    }
//////
//////    /**
//////     * CLINICAL DATA: Saves the list of prescribed medications to the consultation record.
//////     */
//////    @Transactional
//////    public void savePrescriptions(UUID consultationId, List<PrescriptionRequest> requests) {
//////        Consultation consultation = consultationRepository.findById(consultationId)
//////                .orElseThrow(() -> new RuntimeException("Clinical context not found for prescription."));
//////
//////        List<Prescription> prescriptions = requests.stream().map(req ->
//////                Prescription.builder()
//////                        .consultation(consultation)
//////                        .medicineName(req.getMedicineName())
//////                        .dosage(req.getDosage())
//////                        .frequency(req.getFrequency())
//////                        .duration(req.getDuration())
//////                        .instructions(req.getInstructions())
//////                        .build()
//////        ).toList();
//////
//////        prescriptionRepository.saveAll(prescriptions);
//////    }
//////}
//
//
//
//package com.medibot.healthcare_platform.modules.consultation.service;
//
//import com.medibot.healthcare_platform.modules.consultation.dto.PrescriptionRequest;
//import com.medibot.healthcare_platform.modules.consultation.entity.Consultation;
//import com.medibot.healthcare_platform.modules.consultation.entity.Prescription;
//import com.medibot.healthcare_platform.modules.consultation.repository.ConsultationPrescriptionRepository;
//import com.medibot.healthcare_platform.modules.booking.repository.BookingRepository;
//import com.medibot.healthcare_platform.modules.doctor.entity.SlotStatus;
//import com.medibot.healthcare_platform.modules.doctor.repository.SlotRepository;
//import com.medibot.healthcare_platform.modules.notification.service.NotificationService;
//import lombok.RequiredArgsConstructor;
//import org.springframework.stereotype.Service;
//import org.springframework.transaction.annotation.Transactional;
//
//import java.time.LocalDateTime;
//import java.util.List;
//import java.util.UUID;
//
//@Service
//@RequiredArgsConstructor
//public class ConsultationService {
//
//    private final ConsultationPrescriptionRepository consultationRepository;
//    private final BookingRepository bookingRepository;
//    private final SlotRepository slotRepository;
//    private final NotificationService notificationService;
//    private final ConsultationPrescriptionRepository prescriptionRepository;
//
//    /**
//     * START SESSION: Idempotent initialization.
//     */
//    @Transactional
//    public Consultation startConsultation(UUID bookingId) {
//        return consultationRepository.findByBookingId(bookingId)
//                .orElseGet(() -> {
//                    var booking = bookingRepository.findById(bookingId)
//                            .orElseThrow(() -> new RuntimeException("Booking reference not found: " + bookingId));
//
//                    Consultation consultation = Consultation.builder()
//                            .booking(booking)
//                            .startTime(LocalDateTime.now())
//                            .isCompleted(false)
//                            .build();
//                    return consultationRepository.save(consultation);
//                });
//    }
//
//    /**
//     * THE HANDSHAKE: Sets Room ID and alerts the Patient.
//     */
//    @Transactional
//    public void updateRoomId(UUID id, String roomId) {
//        Consultation c = consultationRepository.findById(id)
//                .orElseThrow(() -> new RuntimeException("Consultation not found"));
//
//        c.setRoomId(roomId);
//        consultationRepository.save(c);
//
//        // NOTIFICATION: Trigger persistent alert for Kartik
//        String joinLink = "/patient/consultation/" + c.getBooking().getId();
//        notificationService.createNotification(
//                c.getBooking().getPatient().getId(),
//                "Dr. " + c.getBooking().getSlot().getDoctor().getUser().getFirstName() + " has joined the room. Click to enter.",
//                "CONSULTATION_STARTED",
//                joinLink
//        );
//    }
//
//    /**
//     * ROOM DISCOVERY: Renamed to match Controller's call.
//     */
//    @Transactional(readOnly = true)
//    public String getActiveRoom(UUID bookingId) {
//        return consultationRepository.findByBookingId(bookingId)
//                .map(Consultation::getRoomId)
//                .filter(room -> room != null && !room.isEmpty())
//                .orElseThrow(() -> new RuntimeException("Doctor has not initialized the room yet."));
//    }
//
//    /**
//     * END SESSION: Finalizes record and releases the slot.
//     */
//    @Transactional
//    public void endConsultation(UUID consultationId, String notes) {
//        Consultation c = consultationRepository.findById(consultationId)
//                .orElseThrow(() -> new RuntimeException("Consultation ID not found"));
//
//        c.setEndTime(LocalDateTime.now());
//        c.setDoctorNotes(notes);
//        c.setCompleted(true);
//
//        if (c.getBooking() != null && c.getBooking().getSlot() != null) {
//            var slot = c.getBooking().getSlot();
//            slot.setStatus(SlotStatus.AVAILABLE);
//            slotRepository.save(slot);
//        }
//        consultationRepository.save(c);
//    }
//
//    /**
//     * HISTORY: Fetches clinical record timeline.
//     */
//    public List<Consultation> getPatientConsultationHistory(UUID patientId) {
//        return consultationRepository.findByBookingPatientIdAndIsCompletedTrueOrderByCreatedAtDesc(patientId);
//    }
//
//    /**
//     * PRESCRIPTIONS: Saves medication list.
//     */
//    @Transactional
//    public void savePrescriptions(UUID consultationId, List<PrescriptionRequest> requests) {
//        Consultation consultation = consultationRepository.findById(consultationId)
//                .orElseThrow(() -> new RuntimeException("Consultation context not found."));
//
//        List<Prescription> prescriptions = requests.stream().map(req ->
//                Prescription.builder()
//                        .consultation(consultation)
//                        .medicineName(req.getMedicineName())
//                        .dosage(req.getDosage())
//                        .frequency(req.getFrequency())
//                        .duration(req.getDuration())
//                        .instructions(req.getInstructions())
//                        .build()
//        ).toList();
//
//        prescriptionRepository.saveAll(prescriptions);
//    }
//}





package com.medibot.healthcare_platform.modules.consultation.service;

import com.medibot.healthcare_platform.modules.consultation.dto.PrescriptionRequest;
import com.medibot.healthcare_platform.modules.consultation.entity.Consultation;
import com.medibot.healthcare_platform.modules.consultation.entity.Prescription;
import com.medibot.healthcare_platform.modules.consultation.repository.ConsultationRepository;
import com.medibot.healthcare_platform.modules.consultation.repository.ConsultationPrescriptionRepository; // Renamed
import com.medibot.healthcare_platform.modules.booking.repository.BookingRepository;
import com.medibot.healthcare_platform.modules.doctor.entity.SlotStatus;
import com.medibot.healthcare_platform.modules.doctor.repository.SlotRepository;
import com.medibot.healthcare_platform.modules.notification.service.NotificationService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class ConsultationService {

    private final ConsultationRepository consultationRepository; // Fixed Type
    private final BookingRepository bookingRepository;
    private final SlotRepository slotRepository;
    private final NotificationService notificationService;
    private final ConsultationPrescriptionRepository prescriptionRepository; // Fixed Type & Name

    /**
     * START SESSION: Idempotent logic prevents duplicate sessions if Dr. Elena and Kartik join at once.
     */
    @Transactional
    public Consultation startConsultation(UUID bookingId) {
        return consultationRepository.findByBookingId(bookingId)
                .orElseGet(() -> {
                    var booking = bookingRepository.findById(bookingId)
                            .orElseThrow(() -> new RuntimeException("Booking reference not found: " + bookingId));

                    Consultation consultation = Consultation.builder()
                            .booking(booking)
                            .startTime(LocalDateTime.now())
                            .isCompleted(false)
                            .build();
                    return consultationRepository.save(consultation);
                });
    }

    /**
     * THE HANDSHAKE: Doctor saves the room ID, which triggers a notification for the Patient.
     */
    @Transactional
    public void updateRoomId(UUID id, String roomId) {
        Consultation c = consultationRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Consultation not found"));

        c.setRoomId(roomId);
        consultationRepository.save(c);

        // Notify Kartik that Elena has entered the room
        String joinLink = "/patient/consultation/" + c.getBooking().getId();
        notificationService.createNotification(
                c.getBooking().getPatient().getId(),
                "Dr. " + c.getBooking().getSlot().getDoctor().getUser().getFirstName() + " has joined the room. Click to enter.",
                "CONSULTATION_STARTED",
                joinLink
        );
    }

    /**
     * DISCOVERY: Used by the Patient Dashboard to fetch the Doctor's active Jitsi room.
     */
    @Transactional(readOnly = true)
    public String getActiveRoom(UUID bookingId) {
        return consultationRepository.findByBookingId(bookingId)
                .map(Consultation::getRoomId)
                .filter(room -> room != null && !room.isEmpty())
                .orElseThrow(() -> new RuntimeException("Physician has not initialized the room yet."));
    }

    /**
     * CLINICAL DATA: Saves medication details to the live consultation record.
     */
    @Transactional
    public void savePrescriptions(UUID consultationId, List<PrescriptionRequest> requests) {
        Consultation consultation = consultationRepository.findById(consultationId)
                .orElseThrow(() -> new RuntimeException("Active clinical session not found."));

        List<Prescription> prescriptions = requests.stream().map(req ->
                Prescription.builder()
                        .consultation(consultation)
                        .medicineName(req.getMedicineName())
                        .dosage(req.getDosage())
                        .frequency(req.getFrequency())
                        .duration(req.getDuration())
                        .instructions(req.getInstructions())
                        .build()
        ).toList();

        prescriptionRepository.saveAll(prescriptions);
    }

    /**
     * WRAP-UP: Finalizes clinical notes and marks the slot as AVAILABLE for future patients.
     */
    @Transactional
    public void endConsultation(UUID consultationId, String notes) {
        Consultation c = consultationRepository.findById(consultationId)
                .orElseThrow(() -> new RuntimeException("Consultation ID not found"));

        c.setEndTime(LocalDateTime.now());
        c.setDoctorNotes(notes);
        c.setCompleted(true);

        if (c.getBooking() != null && c.getBooking().getSlot() != null) {
            var slot = c.getBooking().getSlot();
            slot.setStatus(SlotStatus.AVAILABLE);
            slotRepository.save(slot);
        }
        consultationRepository.save(c);
    }

    /**
     * HISTORY: Retrieves all completed records for the Patient timeline.
     */
    public List<Consultation> getPatientConsultationHistory(UUID patientId) {
        return consultationRepository.findByBookingPatientIdAndIsCompletedTrueOrderByCreatedAtDesc(patientId);
    }
}