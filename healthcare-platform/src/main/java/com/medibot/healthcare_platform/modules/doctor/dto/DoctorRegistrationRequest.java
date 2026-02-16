package com.medibot.healthcare_platform.modules.doctor.dto;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import lombok.Data;
import java.util.UUID;

@Data
public class DoctorRegistrationRequest {
    @NotNull(message = "User ID is required")
    private UUID userId;

    @NotNull(message = "Hospital ID is required")
    private UUID hospitalId;

    @NotNull(message = "Department ID is required")
    private UUID departmentId;

    @NotNull(message = "Specialization is required")
    private String specialization;

    @Positive(message = "Consultation fee must be greater than zero")
    private Double consultationFee;

    private String bio;
}