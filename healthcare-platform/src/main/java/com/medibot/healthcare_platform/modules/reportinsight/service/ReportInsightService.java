package com.medibot.healthcare_platform.modules.reportinsight.service;

import com.cloudinary.Cloudinary;
import com.cloudinary.utils.ObjectUtils;
import com.medibot.healthcare_platform.modules.identity.entity.User;
import com.medibot.healthcare_platform.modules.identity.repository.UserRepository;
import com.medibot.healthcare_platform.modules.reportinsight.dto.ReportInsightResponse;
import com.medibot.healthcare_platform.modules.reportinsight.entity.ReportInsight;
import com.medibot.healthcare_platform.modules.reportinsight.repository.ReportInsightRepository;
import com.medibot.healthcare_platform.modules.triage.client.GeminiClient;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.util.Map;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class ReportInsightService {

    private final ReportInsightRepository reportInsightRepository;
    private final UserRepository userRepository;
    private Cloudinary cloudinary;

    @Value("${cloudinary.cloud-name}")
    private String cloudName;

    @Value("${cloudinary.api-key}")
    private String apiKey;

    @Value("${cloudinary.api-secret}")
    private String apiSecret;

    @PostConstruct
    public void init() {
        cloudinary = new Cloudinary(ObjectUtils.asMap(
                "cloud_name", cloudName,
                "api_key", apiKey,
                "api_secret", apiSecret
        ));
    }
    private final GeminiClient geminiClient;

    /**
     * Main orchestration method:
     * 1. Upload image to Cloudinary
     * 2. Call GeminiClient.getImageAnalysis()
     * 3. Parse response using strict delimiter logic (mirrors TriageService pattern)
     * 4. Persist to DB
     * 5. Return structured DTO
     */
    public ReportInsightResponse analyzeReport(MultipartFile file, String patientEmail) {
        log.info("ReportInsightService: Starting analysis for patient: {}", patientEmail);

        // Step 1: Upload to Cloudinary
        String imageUrl = uploadToCloudinary(file);
        log.info("ReportInsightService: Image uploaded to Cloudinary. URL: {}", imageUrl);

        // Step 2: Call Gemini with the new method (does NOT touch getClinicalAdvice)
        String rawGeminiResponse = geminiClient.getImageAnalysis(imageUrl);
        log.info("ReportInsightService: Raw Gemini response received.");

        // Step 3: Parse strictly — same split-by-pipe philosophy as TriageService
        ReportInsightResponse parsed = parseGeminiResponse(rawGeminiResponse);

        // Step 4: Persist
        User patient = userRepository.findByEmail(patientEmail)
                .orElseThrow(() -> new RuntimeException("Patient not found: " + patientEmail));

        ReportInsight insight = ReportInsight.builder()
                .patient(patient)
                .imageUrl(imageUrl)
                .findings(parsed.getFindings())
                .possibleCondition(parsed.getPossibleCondition())
                .recommendations(parsed.getRecommendations())
                .riskLevel(parsed.getRiskLevel())
                .build();

        ReportInsight saved = reportInsightRepository.save(insight);
        log.info("ReportInsightService: Analysis saved with ID: {}", saved.getId());

        // Step 5: Return with ID and imageUrl enriched
        return ReportInsightResponse.builder()
                .id(saved.getId())
                .imageUrl(imageUrl)
                .findings(parsed.getFindings())
                .possibleCondition(parsed.getPossibleCondition())
                .recommendations(parsed.getRecommendations())
                .riskLevel(parsed.getRiskLevel())
                .build();
    }

    /**
     * Parses the structured Gemini response.
     *
     * Expected format:
     * SERVICE: [value] | FINDINGS: [value] | CONDITION: [value] | GUIDELINES: [value] | ALERT: [value]
     *
     * Philosophy: Same as TriageService — split by pipe, then strip key prefix.
     * Defaults are provided for every field in case parsing fails — NEVER throws on parse.
     */
    private ReportInsightResponse parseGeminiResponse(String raw) {
        log.debug("ReportInsightService: Parsing Gemini response.");

        String findings          = "Analysis not available.";
        String possibleCondition = "Could not determine.";
        String recommendations   = "Please consult a certified healthcare provider.";
        String riskLevel         = "UNKNOWN";

        try {
            // Split on the pipe delimiter — same pattern as triage module
            String[] segments = raw.split("\\|");

            for (String segment : segments) {
                String trimmed = segment.trim();

                if (trimmed.startsWith("FINDINGS:")) {
                    findings = trimmed.replaceFirst("FINDINGS:", "").trim();
                } else if (trimmed.startsWith("CONDITION:")) {
                    possibleCondition = trimmed.replaceFirst("CONDITION:", "").trim();
                } else if (trimmed.startsWith("GUIDELINES:")) {
                    recommendations = trimmed.replaceFirst("GUIDELINES:", "").trim();
                } else if (trimmed.startsWith("ALERT:")) {
                    String alertRaw = trimmed.replaceFirst("ALERT:", "").trim();
                    // Extract risk level from ALERT — look for HIGH / MODERATE / LOW keyword
                    riskLevel = extractRiskLevel(alertRaw);
                    // Keep full ALERT text in recommendations if it adds context
                    if (!recommendations.contains(alertRaw)) {
                        recommendations = recommendations + "\n\nAlert: " + alertRaw;
                    }
                }
            }
        } catch (Exception e) {
            log.error("ReportInsightService: Parse error — using safe defaults. Error: {}", e.getMessage());
            // All defaults already set above — safe to continue
        }

        return ReportInsightResponse.builder()
                .findings(findings)
                .possibleCondition(possibleCondition)
                .recommendations(recommendations)
                .riskLevel(riskLevel)
                .build();
    }

    /**
     * Extracts a normalised risk level string from the ALERT segment.
     * Returns "HIGH", "MODERATE", or "LOW". Defaults to "MODERATE" if unclear.
     */
    private String extractRiskLevel(String alertText) {
        String upper = alertText.toUpperCase();
        if (upper.contains("HIGH"))     return "HIGH";
        if (upper.contains("MODERATE")) return "MODERATE";
        if (upper.contains("LOW"))      return "LOW";
        return "MODERATE"; // safe default
    }

    /**
     * Uploads the file to Cloudinary under the 'medibot_reports' folder.
     * Throws RuntimeException on failure so the controller can return 500 cleanly.
     */
    private String uploadToCloudinary(MultipartFile file) {
        try {
            Map<?, ?> result = cloudinary.uploader().upload(
                    file.getBytes(),
                    ObjectUtils.asMap(
                            "folder", "medibot_reports",
                            "resource_type", "auto"
                    )
            );
            return (String) result.get("secure_url");
        } catch (Exception e) {
            log.error("ReportInsightService: Cloudinary upload failed. Error: {}", e.getMessage());
            throw new RuntimeException("Failed to upload image to storage. Please try again.", e);
        }
    }
}