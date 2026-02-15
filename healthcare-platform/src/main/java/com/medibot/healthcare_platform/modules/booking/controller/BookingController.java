package com.medibot.healthcare_platform.modules.booking.controller;

import com.medibot.healthcare_platform.modules.booking.dto.BookingResponse;
import com.medibot.healthcare_platform.modules.booking.service.BookingService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/bookings")
@RequiredArgsConstructor
public class BookingController {

    private final BookingService bookingService;

    /**
     * Dashboard View: Patients get all their bookings (Confirmed, Completed, etc.)
     */
    @GetMapping("/patient/{patientId}")
    @PreAuthorize("hasRole('PATIENT') or hasRole('ADMIN')")
    public ResponseEntity<List<BookingResponse>> getPatientBookings(@PathVariable UUID patientId) {
        return ResponseEntity.ok(bookingService.getPatientBookings(patientId));
    }

    /**
     * Professional View: Doctors see their upcoming appointments to prepare for calls.
     */
    @GetMapping("/doctor/{doctorId}")
    @PreAuthorize("hasRole('DOCTOR')")
    public ResponseEntity<List<BookingResponse>> getDoctorBookings(@PathVariable UUID doctorId) {
        // This leverages the service logic to filter by doctorId
        return ResponseEntity.ok(bookingService.getDoctorBookings(doctorId));
    }

    /**
     * Specific Detail: Get a single booking's details (e.g., to fetch the meeting link).
     */
    @GetMapping("/{bookingId}")
    @PreAuthorize("hasRole('PATIENT') or hasRole('DOCTOR')")
    public ResponseEntity<BookingResponse> getBookingById(@PathVariable UUID bookingId) {
        return ResponseEntity.ok(bookingService.getBookingById(bookingId));
    }
}