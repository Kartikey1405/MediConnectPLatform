//package com.medibot.healthcare_platform.modules.booking.repository;
//
//import com.medibot.healthcare_platform.modules.booking.entity.Booking;
//import org.springframework.data.jpa.repository.JpaRepository;
//import java.util.List;
//import java.util.UUID;
//
//public interface BookingRepository extends JpaRepository<Booking, UUID> {
//    // Find all bookings for a patient, newest first for the dashboard
//    List<Booking> findByPatientIdOrderByCreatedAtDesc(UUID patientId);
//    // Spring Data JPA handles the nested 'slot.doctor.id' traversal automatically
//    List<Booking> findBySlotDoctorIdOrderByCreatedAtDesc(UUID doctorId);
//}



package com.medibot.healthcare_platform.modules.booking.repository;

import com.medibot.healthcare_platform.modules.booking.entity.Booking;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;
import java.util.UUID;

public interface BookingRepository extends JpaRepository<Booking, UUID> {
    // Traverse: Booking -> Patient (mapped as patient_id)
    List<Booking> findByPatientIdOrderByCreatedAtDesc(UUID patientId);

    // Traverse: Booking -> Slot (named slot) -> Doctor (named doctor) -> id
    List<Booking> findBySlotDoctorIdOrderByCreatedAtDesc(UUID doctorId);
}