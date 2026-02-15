package com.medibot.healthcare_platform.modules.triage.controller;

import com.medibot.healthcare_platform.modules.triage.dto.TriageResponse;
import com.medibot.healthcare_platform.modules.triage.service.TriageService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/triage")
@RequiredArgsConstructor
public class TriageController {

    private final TriageService triageService;

    /**
     * Endpoint for the "Symptom Checker" on the website homepage.
     * Example input: ["fever", "cough", "shortness of breath"]
     */
    @PostMapping("/analyze")
    public ResponseEntity<TriageResponse> analyzeSymptoms(@RequestBody List<String> symptoms) {
        if (symptoms == null || symptoms.isEmpty()) {
            return ResponseEntity.badRequest().build();
        }
        return ResponseEntity.ok(triageService.analyzeSymptoms(symptoms));
    }
}