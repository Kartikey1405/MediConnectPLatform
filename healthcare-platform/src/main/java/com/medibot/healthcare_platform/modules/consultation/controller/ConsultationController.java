package com.medibot.healthcare_platform.modules.consultation.controller;

import com.medibot.healthcare_platform.modules.consultation.entity.Consultation;
import com.medibot.healthcare_platform.modules.consultation.service.ConsultationService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import java.util.UUID;

@RestController
@RequestMapping("/api/consultations")
@RequiredArgsConstructor
public class ConsultationController {
    private final ConsultationService consultationService;

    @PostMapping("/start/{bookingId}")
    @PreAuthorize("hasRole('DOCTOR')")
    public ResponseEntity<Consultation> start(@PathVariable UUID bookingId) {
        return ResponseEntity.ok(consultationService.startConsultation(bookingId));
    }

    @PatchMapping("/end/{id}")
    @PreAuthorize("hasRole('DOCTOR')")
    public ResponseEntity<String> end(@PathVariable UUID id, @RequestBody String notes) {
        consultationService.endConsultation(id, notes);
        return ResponseEntity.ok("Consultation ended and notes saved.");
    }
}