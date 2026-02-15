//package com.medibot.healthcare_platform.modules.doctor.controller;
//
//import com.medibot.healthcare_platform.modules.doctor.entity.Slot;
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
//
//@RestController
//@RequestMapping("/api/doctor")
//@RequiredArgsConstructor
//public class DoctorController {
//
//    private final DoctorService doctorService;
//
//    /**
//     * Endpoint for doctors to generate their own 30-min slots.
//     * Expects ISO date format: 2026-02-10T09:00:00
//     */
//    @PostMapping("/{doctorId}/slots/generate")
//    @PreAuthorize("hasRole('DOCTOR')")
//    public ResponseEntity<List<Slot>> generateAvailability(
//            @PathVariable UUID doctorId,
//            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime start,
//            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime end) {
//
//        return ResponseEntity.ok(doctorService.generateSlots(doctorId, start, end));
//    }
//}

package com.medibot.healthcare_platform.modules.doctor.controller;

import com.medibot.healthcare_platform.modules.doctor.dto.SlotResponse;
import com.medibot.healthcare_platform.modules.doctor.service.DoctorService;
import lombok.RequiredArgsConstructor;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/doctor")
@RequiredArgsConstructor
public class DoctorController {

    private final DoctorService doctorService;

    /**
     * Endpoint for doctors to generate their own 30-min slots.
     */
    @PostMapping("/{doctorId}/slots/generate")
    @PreAuthorize("hasRole('DOCTOR')")
    public ResponseEntity<List<SlotResponse>> generateAvailability(
            @PathVariable UUID doctorId,
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime start,
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime end) {

        // We use the service to generate, then map to Response DTOs
        List<SlotResponse> responses = doctorService.generateSlots(doctorId, start, end)
                .stream()
                .map(slot -> SlotResponse.builder()
                        .id(slot.getId())
                        .startTime(slot.getStartTime())
                        .endTime(slot.getEndTime())
                        .status(slot.getStatus().name())
                        .build())
                .collect(Collectors.toList());

        return ResponseEntity.ok(responses);
    }
}