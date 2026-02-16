package com.medibot.healthcare_platform.modules.triage.dto;

import lombok.Data;
import java.util.List;

@Data
public class TriageRequest {
    private List<String> symptoms;
}