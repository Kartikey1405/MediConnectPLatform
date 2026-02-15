package com.medibot.healthcare_platform.modules.booking.dto;

import lombok.Builder;
import lombok.Data;
import java.time.LocalDateTime;
import java.util.UUID;

@Data
@Builder
public class BookingResponse {
    private UUID bookingId;
    private String doctorName;
    private LocalDateTime appointmentTime;
    private String status;
    private String meetingLink;
}