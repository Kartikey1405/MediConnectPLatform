package com.medibot.healthcare_platform.modules.hospital.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class HospitalRequest {
    @NotBlank(message = "Hospital name is required")
    private String name;

    @NotBlank(message = "Address is required")
    private String address;

    private Double latitude;
    private Double longitude;
    private String contactNumber;
}