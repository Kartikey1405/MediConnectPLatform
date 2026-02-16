//package com.medibot.healthcare_platform.modules.triage.controller;
//
//import com.medibot.healthcare_platform.modules.triage.dto.TriageResponse;
//import com.medibot.healthcare_platform.modules.triage.service.TriageService;
//import lombok.RequiredArgsConstructor;
//import org.springframework.http.ResponseEntity;
//import org.springframework.web.bind.annotation.*;
//
//import java.util.List;
//
//@RestController
//@RequestMapping("/api/triage")
//@RequiredArgsConstructor
//public class TriageController {
//
//    private final TriageService triageService;
//
//    /**
//     * Endpoint for the "Symptom Checker" on the website homepage.
//     * Example input: ["fever", "cough", "shortness of breath"]
//     */
//    @PostMapping("/analyze")
//    public ResponseEntity<TriageResponse> analyzeSymptoms(@RequestBody List<String> symptoms) {
//        if (symptoms == null || symptoms.isEmpty()) {
//            return ResponseEntity.badRequest().build();
//        }
//        return ResponseEntity.ok(triageService.analyzeSymptoms(symptoms));
//    }
//}



package com.medibot.healthcare_platform.modules.triage.controller;

import com.medibot.healthcare_platform.modules.triage.dto.TriageRequest;
import com.medibot.healthcare_platform.modules.triage.dto.TriageResponse;
import com.medibot.healthcare_platform.modules.triage.service.TriageService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/triage")
@RequiredArgsConstructor
@Slf4j
public class TriageController {

    private final TriageService triageService;

    /**
     * Endpoint for the AI-powered Symptom Checker.
     * Takes symptoms from the frontend and returns disease prediction + Gemini advice.
     */
    @PostMapping("/analyze")
    public ResponseEntity<TriageResponse> analyzeSymptoms(@Valid @RequestBody TriageRequest request) {
        // Validation check for empty symptom list
        if (request.getSymptoms() == null || request.getSymptoms().isEmpty()) {
            log.warn("Empty triage request received.");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        }

        try {
            log.info("Processing triage for symptoms: {}", request.getSymptoms());
            TriageResponse response = triageService.analyzeSymptoms(request.getSymptoms());
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Triage analysis failed: {}", e.getMessage());
            // Return internal error if AI models are unreachable
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).build();
        }
    }
}