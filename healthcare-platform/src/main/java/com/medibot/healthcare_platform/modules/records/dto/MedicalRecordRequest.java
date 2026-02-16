package com.medibot.healthcare_platform.modules.records.dto;

import lombok.Data;
import java.util.List;

@Data
public class MedicalRecordRequest {
    private String diagnosis;
    private String symptoms;
    private List<PrescriptionRequest> prescriptions;
}