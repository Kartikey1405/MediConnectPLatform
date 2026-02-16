package com.medibot.healthcare_platform.modules.hospital.controller;

import com.medibot.healthcare_platform.modules.hospital.dto.HospitalResponse;
import com.medibot.healthcare_platform.modules.hospital.service.HospitalService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/hospitals")
@RequiredArgsConstructor
public class HospitalController {

    private final HospitalService hospitalService;

    @GetMapping
    public ResponseEntity<List<HospitalResponse>> getAllHospitals() {
        return ResponseEntity.ok(hospitalService.getAllHospitals());
    }

    /**
     * SOS Feature: Added @RequestParam to fix the previous "Invalid mapping" crash.
     */
    @GetMapping("/sos")
    public ResponseEntity<List<HospitalResponse>> getNearestEmergencyHospitals(
            @RequestParam double lat,
            @RequestParam double lng) {
        return ResponseEntity.ok(hospitalService.getSOSNearHospitals(lat, lng));
    }
}