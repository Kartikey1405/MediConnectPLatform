package com.medibot.healthcare_platform.modules.reportinsight.controller;

import com.medibot.healthcare_platform.modules.reportinsight.dto.ReportInsightResponse;
import com.medibot.healthcare_platform.modules.reportinsight.service.ReportInsightService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/api/report-insight")
@RequiredArgsConstructor
@Slf4j
public class ReportInsightController {

    private final ReportInsightService reportInsightService;

    /**
     * POST /api/report-insight/analyze
     *
     * Accepts a medical image file, runs AI analysis, and returns structured findings.
     * Secured to PATIENT role only — same pattern as /api/maps/** and /api/triage/**.
     */
    @PostMapping(value = "/analyze", consumes = "multipart/form-data")
    @PreAuthorize("hasRole('PATIENT')")
    public ResponseEntity<ReportInsightResponse> analyzeReport(
            @RequestParam("file") MultipartFile file,
            Authentication authentication) {

        if (file == null || file.isEmpty()) {
            log.warn("ReportInsightController: Empty file received.");
            return ResponseEntity.badRequest().build();
        }

        // Extract email from JWT principal — same as other secured endpoints
        String patientEmail = authentication.getName();
        log.info("ReportInsightController: Analysis request from: {}", patientEmail);

        ReportInsightResponse response = reportInsightService.analyzeReport(file, patientEmail);
        return ResponseEntity.ok(response);
    }
}