package com.medibot.healthcare_platform.modules.records.dto;

import lombok.Data;

@Data
public class PrescriptionRequest {
    private String medicineName;
    private String dosage;
    private String frequency;
    private String duration;
    private String instructions;
}