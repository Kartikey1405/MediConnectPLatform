package com.medibot.healthcare_platform.modules.records.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class PrescriptionDTO {
    private String medicineName;
    private String dosage;
    private String frequency;
    private String instructions;
}