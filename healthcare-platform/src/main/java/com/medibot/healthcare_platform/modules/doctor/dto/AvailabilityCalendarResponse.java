// AvailabilityCalendarResponse.java
package com.medibot.healthcare_platform.modules.doctor.dto;

import lombok.Builder;
import lombok.Data;
import java.time.LocalDate;
import java.util.List;

@Data
@Builder
public class AvailabilityCalendarResponse {
    private LocalDate date;
    private boolean available;
    private List<SlotResponse> slots; // populated slots for that day
}