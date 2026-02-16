package com.medibot.healthcare_platform.modules.triage.controller;

import com.medibot.healthcare_platform.modules.triage.entity.TriageHistory;
import com.medibot.healthcare_platform.modules.triage.service.TriageHistoryService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/triage/history")
@RequiredArgsConstructor
public class TriageHistoryController {

    private final TriageHistoryService triageHistoryService;

    /**
     * Endpoint to save a successful AI Triage result to the patient's timeline.
     * Triggered by the "Save to Recalls" button in the frontend.
     */
    @PostMapping("/save/{patientId}")
    @PreAuthorize("hasRole('PATIENT')")
    public ResponseEntity<String> saveToTimeline(
            @PathVariable UUID patientId,
            @RequestParam String disease,
            @RequestParam double confidence,
            @RequestParam String symptoms,
            @RequestBody List<String> tips) {

        triageHistoryService.saveTriageResult(patientId, disease, confidence, symptoms, tips);
        return ResponseEntity.ok("Successfully saved to your timeline.");
    }

    /**
     * Endpoint to fetch the complete triage journey for a patient.
     * Used to populate the Timeline.tsx component.
     */
    @GetMapping("/patient/{patientId}")
    @PreAuthorize("hasRole('PATIENT') or hasRole('ADMIN')")
    public ResponseEntity<List<TriageHistory>> getPatientTimeline(@PathVariable UUID patientId) {
        return ResponseEntity.ok(triageHistoryService.getHistoryByPatient(patientId));
    }

    /**
     * Allows a patient to remove an entry from their history.
     */
    @DeleteMapping("/{historyId}")
    @PreAuthorize("hasRole('PATIENT')")
    public ResponseEntity<Void> deleteHistoryEntry(@PathVariable UUID historyId) {
        triageHistoryService.deleteEntry(historyId);
        return ResponseEntity.noContent().build();
    }
}