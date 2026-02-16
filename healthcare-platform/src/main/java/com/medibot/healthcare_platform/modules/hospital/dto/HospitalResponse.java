

//@Data
//@Builder
//public class HospitalResponse {
//    private UUID id;
//    private String name;
//    private String address;
//    private String contactNumber;
//    private String description; // Brief overview of the hospital
//    private Double rating;      // Important for SOS/Discovery filtering
//    private String imageUrl;    // For the "Find Doctor" UI cards
//    private Double latitude;
//    private Double longitude;
//    private List<DepartmentResponse> departments; // Nested structure for department-wise view
//}


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
    private String description;
    private Double rating;
    private String imageUrl;
    private Double latitude;
    private Double longitude;

    @Builder.Default // Ensures this is never null when the frontend receives it
    private List<DepartmentResponse> departments = new java.util.ArrayList<>();
}