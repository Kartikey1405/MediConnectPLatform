package com.medibot.healthcare_platform.modules.hospital.dto;

import lombok.Builder;
import lombok.Data;
import java.util.UUID;

@Data
@Builder
public class DepartmentResponse {
    private UUID id;
    private String name;
    private String specialty;
    private Double consultationFee; // Added for the Payment/Video Call logic
}