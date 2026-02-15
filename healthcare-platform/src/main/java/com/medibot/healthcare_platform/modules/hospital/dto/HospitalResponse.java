package com.medibot.healthcare_platform.modules.hospital.dto;

import lombok.Builder;
import lombok.Data;
import java.util.List;
import java.util.UUID;

@Data
@Builder
public class HospitalResponse {
    private UUID id;
    private String name;
    private String address;
    private String contactNumber;
    private Double latitude;
    private Double longitude;
    private List<DepartmentResponse> departments;
}