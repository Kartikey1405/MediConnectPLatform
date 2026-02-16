package com.medibot.healthcare_platform.modules.hospital.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import lombok.Data;
import java.util.UUID;

@Data
public class DepartmentRequest {
    @NotBlank(message = "Department name is required")
    private String name;

    @NotBlank(message = "Specialty is required")
    private String specialty;

    @NotNull(message = "Consultation fee is required")
    @Positive(message = "Fee must be greater than zero")
    private Double consultationFee;

    @NotNull(message = "Hospital ID is required")
    private UUID hospitalId;
}