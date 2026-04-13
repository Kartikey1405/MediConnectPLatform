// SlotTemplateRequest.java
package com.medibot.healthcare_platform.modules.doctor.dto;

import lombok.Data;
import java.time.LocalTime;

@Data
public class SlotTemplateRequest {
    private String label;       // "Morning Session"
    private LocalTime startTime; // 09:30
    private LocalTime endTime;   // 11:00
}