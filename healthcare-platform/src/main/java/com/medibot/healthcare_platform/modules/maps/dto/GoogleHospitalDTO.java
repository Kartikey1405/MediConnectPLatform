package com.medibot.healthcare_platform.modules.maps.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class GoogleHospitalDTO {
    private String placeId; // String, not UUID
    private String name;
    private String address;
    private Double rating;
    private Double latitude;
    private Double longitude;
    private String businessStatus;
    private String distanceText; // e.g. "1.2 km"
}