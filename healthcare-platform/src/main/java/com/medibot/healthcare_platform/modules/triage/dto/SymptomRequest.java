package com.medibot.healthcare_platform.modules.triage.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import java.util.List;

@Data
@AllArgsConstructor
public class SymptomRequest {
    private List<String> symptoms;
}