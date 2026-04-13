//////package com.medibot.healthcare_platform.modules.doctor.controller;
//////
//////import com.medibot.healthcare_platform.modules.doctor.entity.Slot;
//////import com.medibot.healthcare_platform.modules.doctor.service.DoctorService;
//////import lombok.RequiredArgsConstructor;
//////import org.springframework.format.annotation.DateTimeFormat;
//////import org.springframework.http.ResponseEntity;
//////import org.springframework.security.access.prepost.PreAuthorize;
//////import org.springframework.web.bind.annotation.*;
//////
//////import java.time.LocalDateTime;
//////import java.util.List;
//////import java.util.UUID;
//////
//////@RestController
//////@RequestMapping("/api/doctor")
//////@RequiredArgsConstructor
//////public class DoctorController {
//////
//////    private final DoctorService doctorService;
//////
//////    /**
//////     * Endpoint for doctors to generate their own 30-min slots.
//////     * Expects ISO date format: 2026-02-10T09:00:00
//////     */
//////    @PostMapping("/{doctorId}/slots/generate")
//////    @PreAuthorize("hasRole('DOCTOR')")
//////    public ResponseEntity<List<Slot>> generateAvailability(
//////            @PathVariable UUID doctorId,
//////            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime start,
//////            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime end) {
//////
//////        return ResponseEntity.ok(doctorService.generateSlots(doctorId, start, end));
//////    }
//////}
////
////package com.medibot.healthcare_platform.modules.doctor.controller;
////
////import com.medibot.healthcare_platform.modules.doctor.dto.SlotResponse;
////import com.medibot.healthcare_platform.modules.doctor.service.DoctorService;
////import lombok.RequiredArgsConstructor;
////import org.springframework.format.annotation.DateTimeFormat;
////import org.springframework.http.ResponseEntity;
////import org.springframework.security.access.prepost.PreAuthorize;
////import org.springframework.web.bind.annotation.*;
////
////import java.time.LocalDateTime;
////import java.util.List;
////import java.util.UUID;
////import java.util.stream.Collectors;
////
////@RestController
////@RequestMapping("/api/doctor")
////@RequiredArgsConstructor
////public class DoctorController {
////
////    private final DoctorService doctorService;
////
////    /**
////     * Endpoint for doctors to generate their own 30-min slots.
////     */
////    @PostMapping("/{doctorId}/slots/generate")
////    @PreAuthorize("hasRole('DOCTOR')")
////    public ResponseEntity<List<SlotResponse>> generateAvailability(
////            @PathVariable UUID doctorId,
////            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime start,
////            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime end) {
////
////        // We use the service to generate, then map to Response DTOs
////        List<SlotResponse> responses = doctorService.generateSlots(doctorId, start, end)
////                .stream()
////                .map(slot -> SlotResponse.builder()
////                        .id(slot.getId())
////                        .startTime(slot.getStartTime())
////                        .endTime(slot.getEndTime())
////                        .status(slot.getStatus().name())
////                        .build())
////                .collect(Collectors.toList());
////
////        return ResponseEntity.ok(responses);
////    }
////}
//
//
//
//
//package com.medibot.healthcare_platform.modules.doctor.controller;
//
//import com.medibot.healthcare_platform.modules.doctor.dto.SlotResponse;
//import com.medibot.healthcare_platform.modules.doctor.entity.Doctor;
//import com.medibot.healthcare_platform.modules.doctor.repository.DoctorRepository;
//import com.medibot.healthcare_platform.modules.doctor.service.DoctorService;
//import lombok.RequiredArgsConstructor;
//import org.springframework.format.annotation.DateTimeFormat;
//import org.springframework.http.ResponseEntity;
//import org.springframework.security.access.prepost.PreAuthorize;
//import org.springframework.web.bind.annotation.*;
//
//import java.time.LocalDateTime;
//import java.util.List;
//import java.util.UUID;
//import java.util.stream.Collectors;
//
//@RestController
//@RequestMapping("/api/doctor")
//@RequiredArgsConstructor
//public class DoctorController {
//
//    private final DoctorService doctorService;
//    private final DoctorRepository doctorRepository;
//
//    /**
//     * Dashboard Handshake: Allows a doctor to fetch their OWN profile securely.
//     * Fixes the 403 Forbidden error seen in the browser.
//     */
//    @GetMapping("/me/{userId}")
//    @PreAuthorize("hasRole('DOCTOR')")
//    public ResponseEntity<Doctor> getMyDoctorProfile(@PathVariable UUID userId) {
//        return doctorRepository.findByUserId(userId)
//                .map(ResponseEntity::ok)
//                .orElse(ResponseEntity.notFound().build());
//    }
//
//    @PostMapping("/{doctorId}/slots/generate")
//    @PreAuthorize("hasRole('DOCTOR')")
//    public ResponseEntity<List<SlotResponse>> generateAvailability(
//            @PathVariable UUID doctorId,
//            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime start,
//            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime end) {
//
//        List<SlotResponse> responses = doctorService.generateSlots(doctorId, start, end)
//                .stream()
//                .map(slot -> SlotResponse.builder()
//                        .id(slot.getId())
//                        .startTime(slot.getStartTime())
//                        .endTime(slot.getEndTime())
//                        .status(slot.getStatus().name())
//                        .build())
//                .collect(Collectors.toList());
//
//        return ResponseEntity.ok(responses);
//    }
//}






package com.medibot.healthcare_platform.modules.doctor.controller;

import com.medibot.healthcare_platform.modules.doctor.dto.*;
import com.medibot.healthcare_platform.modules.doctor.entity.*;
import com.medibot.healthcare_platform.modules.doctor.service.DoctorService;
import com.medibot.healthcare_platform.modules.doctor.repository.DoctorRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDate;
import java.util.List;
import java.util.UUID;

@RestController
@RequiredArgsConstructor
public class DoctorController {

    private final DoctorService doctorService;
    private final DoctorRepository doctorRepository;

    // ── PUBLIC ───────────────────────────────────────────────────────────────



    @GetMapping("/api/doctor/department/{deptId}")
    public ResponseEntity<List<DoctorResponse>> getByDept(@PathVariable UUID deptId) {
        return ResponseEntity.ok(
                doctorService.getVerifiedDoctorsByDept(deptId)
                        .stream().map(doctorService::mapToDoctorResponse).toList()
        );
    }

    /**
     * Patient: Get 30-day calendar showing which dates have available slots.
     */
    @GetMapping("/api/public/doctors/{doctorId}/calendar")
    public ResponseEntity<List<AvailabilityCalendarResponse>> getCalendar(
            @PathVariable UUID doctorId,
            @RequestParam(required = false)
            @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate from,
            @RequestParam(required = false)
            @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate to) {

        LocalDate start = from != null ? from : LocalDate.now();
        LocalDate end = to != null ? to : start.plusDays(30);
        return ResponseEntity.ok(doctorService.getCalendarForPatient(doctorId, start, end));
    }

    /**
     * Patient: Get available slots for a specific date after picking on calendar.
     */
    @GetMapping("/api/public/doctors/{doctorId}/slots")
    public ResponseEntity<List<SlotResponse>> getSlotsForDate(
            @PathVariable UUID doctorId,
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate date) {
        return ResponseEntity.ok(doctorService.getAvailableSlotsForDate(doctorId, date));
    }

    // ── DOCTOR (Authenticated) ────────────────────────────────────────────────

    /**
     * Doctor: Save their 3 session windows (done once in settings).
     */
    @PostMapping("/api/doctor/templates")
    @PreAuthorize("hasRole('DOCTOR')")
    public ResponseEntity<List<DoctorSlotTemplate>> saveTemplates(
            @RequestParam UUID doctorId,
            @RequestBody List<SlotTemplateRequest> requests) {
        return ResponseEntity.ok(doctorService.saveSlotTemplates(doctorId, requests));
    }

    @GetMapping("/api/doctor/templates")
    @PreAuthorize("hasRole('DOCTOR')")
    public ResponseEntity<List<DoctorSlotTemplate>> getTemplates(@RequestParam UUID doctorId) {
        return ResponseEntity.ok(doctorService.getSlotTemplates(doctorId));
    }

    /**
     * Doctor: Mark specific dates as unavailable (day off).
     */
    @PostMapping("/api/doctor/availability/unavailable")
    @PreAuthorize("hasRole('DOCTOR')")
    public ResponseEntity<String> markUnavailable(
            @RequestParam UUID doctorId,
            @RequestBody List<LocalDate> dates) {
        doctorService.markUnavailableDates(doctorId, dates);
        return ResponseEntity.ok("Dates marked as unavailable.");
    }

    /**
     * Doctor: Mark a date back as available (re-enables slots).
     */
    @PostMapping("/api/doctor/availability/available")
    @PreAuthorize("hasRole('DOCTOR')")
    public ResponseEntity<String> markAvailable(
            @RequestParam UUID doctorId,
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate date) {
        doctorService.markDateAvailable(doctorId, date);
        return ResponseEntity.ok("Date marked as available.");
    }


}