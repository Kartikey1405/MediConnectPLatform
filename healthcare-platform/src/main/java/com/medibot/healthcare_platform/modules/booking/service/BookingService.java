//package com.medibot.healthcare_platform.modules.booking.service;
//
//import com.medibot.healthcare_platform.modules.booking.dto.BookingResponse;
//import com.medibot.healthcare_platform.modules.booking.entity.*;
//import com.medibot.healthcare_platform.modules.booking.repository.BookingRepository;
//import com.medibot.healthcare_platform.modules.payment.entity.TransactionLog;
//import lombok.RequiredArgsConstructor;
//import org.springframework.stereotype.Service;
//import org.springframework.transaction.annotation.Transactional;
//
//import java.util.List;
//import java.util.UUID;
//import java.util.stream.Collectors;
//
//@Service
//@RequiredArgsConstructor
//public class BookingService {
//
//    private final BookingRepository bookingRepository;
//
//    /**
//     * Called automatically after Payment verification logic.
//     * Links the verified payment to a new Booking.
//     */
//    @Transactional
//    public Booking confirmBooking(TransactionLog transaction) {
//        Booking booking = Booking.builder()
//                .patient(transaction.getPatient())
//                .slot(transaction.getSlot())
//                .transaction(transaction)
//                .status(BookingStatus.CONFIRMED)
//                .meetingLink(transaction.getMeetingLink())
//                .build();
//
//        return bookingRepository.save(booking);
//    }
//
//    public List<BookingResponse> getPatientBookings(UUID patientId) {
//        return bookingRepository.findByPatientIdOrderByCreatedAtDesc(patientId).stream()
//                .map(this::mapToResponse)
//                .collect(Collectors.toList());
//    }
//
//    private BookingResponse mapToResponse(Booking booking) {
//        return BookingResponse.builder()
//                .bookingId(booking.getId())
//                .doctorName(booking.getSlot().getDoctor().getUser().getFirstName() + " " +
//                        booking.getSlot().getDoctor().getUser().getLastName())
//                .appointmentTime(booking.getSlot().getStartTime())
//                .status(booking.getStatus().name())
//                .meetingLink(booking.getMeetingLink())
//                .build();
//    }
//
//    public List<BookingResponse> getDoctorBookings(UUID doctorId) {
//        return bookingRepository.findBySlotDoctorIdOrderByCreatedAtDesc(doctorId).stream()
//                .map(this::mapToResponse)
//                .collect(Collectors.toList());
//    }
//
//    public BookingResponse getBookingById(UUID bookingId) {
//        Booking booking = bookingRepository.findById(bookingId)
//                .orElseThrow(() -> new RuntimeException("Booking not found"));
//        return mapToResponse(booking);
//    }
//}







package com.medibot.healthcare_platform.modules.booking.service;

import com.medibot.healthcare_platform.modules.booking.dto.BookingResponse;
import com.medibot.healthcare_platform.modules.booking.entity.*;
import com.medibot.healthcare_platform.modules.booking.repository.BookingRepository;
import com.medibot.healthcare_platform.modules.payment.entity.TransactionLog;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class BookingService {

    private final BookingRepository bookingRepository;

    /**
     * Called automatically after Payment verification logic.
     */
    @Transactional
    public Booking confirmBooking(TransactionLog transaction) {
        Booking booking = Booking.builder()
                .patient(transaction.getPatient())
                .slot(transaction.getSlot())
                .transaction(transaction)
                .status(BookingStatus.CONFIRMED)
                .meetingLink(transaction.getMeetingLink())
                .build();

        return bookingRepository.save(booking);
    }

    public List<BookingResponse> getPatientBookings(UUID patientId) {
        return bookingRepository.findByPatientIdOrderByCreatedAtDesc(patientId).stream()
                .map(this::mapToResponse)
                .collect(Collectors.toList());
    }

    public List<BookingResponse> getDoctorBookings(UUID doctorId) {
        return bookingRepository.findBySlotDoctorIdOrderByCreatedAtDesc(doctorId).stream()
                .map(this::mapToResponse)
                .collect(Collectors.toList());
    }

    public BookingResponse getBookingById(UUID bookingId) {
        Booking booking = bookingRepository.findById(bookingId)
                .orElseThrow(() -> new RuntimeException("Booking not found"));
        return mapToResponse(booking);
    }

    /**
     * Corrected Mapping logic to handle the new DTO fields.
     */
    private BookingResponse mapToResponse(Booking booking) {
        return BookingResponse.builder()
                .bookingId(booking.getId())
                // Fetches Doctor name for the Patient
                .doctorName(booking.getSlot().getDoctor().getUser().getFirstName() + " " +
                        booking.getSlot().getDoctor().getUser().getLastName())
                // NEW: Fetches Patient name for the Doctor
                .patientName(booking.getPatient().getFirstName() + " " +
                        booking.getPatient().getLastName())
                .appointmentTime(booking.getSlot().getStartTime())
                .status(booking.getStatus().name())
                .meetingLink(booking.getMeetingLink())
                .build();
    }
}