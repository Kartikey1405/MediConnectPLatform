package com.medibot.healthcare_platform.modules.hospital.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import lombok.Data;

@Data
public class HospitalRequest {
    @NotBlank(message = "Hospital name is required")
    private String name;

    @NotBlank(message = "Address is required")
    private String address;

    @NotNull(message = "Latitude is required for SOS features")
    private Double latitude;

    @NotNull(message = "Longitude is required for SOS features")
    private Double longitude;

    @Pattern(regexp = "^\\+?[0-9]{10,15}$", message = "Invalid contact number format")
    private String contactNumber;

    private String description;
}