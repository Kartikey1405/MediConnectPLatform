package com.medibot.healthcare_platform.modules.hospital.controller;

import com.medibot.healthcare_platform.modules.hospital.entity.Hospital;
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
    public ResponseEntity<List<Hospital>> getAllHospitalsForPublic() {
        return ResponseEntity.ok(hospitalService.getAllHospitals());
    }
}