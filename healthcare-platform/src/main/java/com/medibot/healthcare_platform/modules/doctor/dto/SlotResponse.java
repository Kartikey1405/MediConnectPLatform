//package com.medibot.healthcare_platform.modules.doctor.dto;
//
//import lombok.Builder;
//import lombok.Data;
//import java.time.LocalDateTime;
//import java.util.UUID;
//
//@Data
//@Builder
//public class SlotResponse {
//    private UUID id;
//    private LocalDateTime startTime;
//    private LocalDateTime endTime;
//    private String status; // String representation of the Enum
//}














package com.medibot.healthcare_platform.modules.doctor.dto;

import lombok.Builder;
import lombok.Data;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.UUID;

@Data
@Builder
public class SlotResponse {
    private UUID id;
    private LocalDate date;
    private LocalDateTime startTime;
    private LocalDateTime endTime;
    private String label;   // "Morning Session", "Afternoon Session", etc.
    private String status;
}