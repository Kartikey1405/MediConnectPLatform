package com.medibot.healthcare_platform.modules.triage.dto;

import lombok.Data;
import java.util.List;

@Data
public class FastApiResponse {
    private List<PredictionData> predictions;
    private String error;

    @Data
    public static class PredictionData {
        private String disease;
        private double confidence;
    }
}