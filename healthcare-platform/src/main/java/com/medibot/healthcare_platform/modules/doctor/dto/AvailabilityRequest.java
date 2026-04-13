// AvailabilityRequest.java
package com.medibot.healthcare_platform.modules.doctor.dto;

import lombok.Data;
import java.time.LocalDate;
import java.util.List;

@Data
public class AvailabilityRequest {
    private List<LocalDate> unavailableDates; // Dates to mark as OFF
}