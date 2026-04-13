package com.medibot.healthcare_platform.modules.reportinsight.dto;

import lombok.Builder;
import lombok.Data;
import java.util.UUID;

@Data
@Builder
public class ReportInsightResponse {
    private UUID id;
    private String imageUrl;
    private String findings;
    private String possibleCondition;
    private String recommendations;
    private String riskLevel;
}