package com.medibot.healthcare_platform.modules.records.dto;

import lombok.Builder;
import lombok.Data;
import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

@Data
@Builder
public class MedicalRecordResponse {
    private UUID id;
    private String doctorName;
    private String diagnosis;
    private String symptoms;
    private List<PrescriptionDTO> prescriptions;
    private LocalDateTime date;
}