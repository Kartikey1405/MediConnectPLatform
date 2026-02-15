package com.medibot.healthcare_platform.modules.doctor.controller;

import com.medibot.healthcare_platform.modules.doctor.entity.Doctor;
import com.medibot.healthcare_platform.modules.doctor.service.DoctorService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/admin/doctors")
@RequiredArgsConstructor
public class AdminDoctorController {

    private final DoctorService doctorService;

    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<Doctor>> getAllDoctors() {
        // We'll use the inherited findAll from JpaRepository via Service
        return ResponseEntity.ok(doctorService.getAllDoctors());
    }

    @PatchMapping("/{id}/verify")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<String> verifyDoctor(@PathVariable UUID id) {
        doctorService.verifyDoctor(id);
        return ResponseEntity.ok("Doctor verified successfully. They are now visible to patients.");
    }
}