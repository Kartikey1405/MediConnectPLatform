package com.medibot.healthcare_platform.modules.triage.dto;

import lombok.Builder;
import lombok.Data;
import java.util.List;

@Data
@Builder
public class TriageResponse {
    private String predictedDisease;
    private double confidence;
    private String recommendedDepartment;

    // These come from the Gemini API integration
    private List<String> preventionSteps;
    private String warningSign;
}