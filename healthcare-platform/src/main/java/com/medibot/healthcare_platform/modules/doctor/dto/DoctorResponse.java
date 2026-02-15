package com.medibot.healthcare_platform.modules.doctor.dto;

import lombok.Builder;
import lombok.Data;
import java.util.UUID;

@Data
@Builder
public class DoctorResponse {
    private UUID id;
    private String fullName; // Combined from User entity
    private String email;
    private String specialization;
    private String departmentName;
    private String hospitalName;
    private Double consultationFee;
    private String bio;
    private boolean isVerified;
}