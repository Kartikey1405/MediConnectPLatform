////package com.medibot.healthcare_platform.modules.doctor.service;
////
////import com.medibot.healthcare_platform.modules.doctor.dto.DoctorResponse;
////import com.medibot.healthcare_platform.modules.doctor.dto.SlotResponse;
////import com.medibot.healthcare_platform.modules.doctor.entity.Doctor;
////import com.medibot.healthcare_platform.modules.doctor.entity.Slot;
////import com.medibot.healthcare_platform.modules.doctor.entity.SlotStatus;
////import com.medibot.healthcare_platform.modules.doctor.repository.DoctorRepository;
////import com.medibot.healthcare_platform.modules.doctor.repository.SlotRepository;
////import com.medibot.healthcare_platform.modules.hospital.entity.Hospital;
////import com.medibot.healthcare_platform.modules.hospital.repository.HospitalRepository;
////import lombok.RequiredArgsConstructor;
////import org.springframework.stereotype.Service;
////import org.springframework.transaction.annotation.Transactional;
////
////import java.time.LocalDateTime;
////import java.util.ArrayList;
////import java.util.List;
////import java.util.UUID;
////
////@Service
////@RequiredArgsConstructor
////public class DoctorService {
////
////    private final DoctorRepository doctorRepository;
////    private final SlotRepository slotRepository;
////    private final HospitalRepository hospitalRepository;
////
////    /**
////     * Completes the Doctor onboarding.
////     * In production, this would be called after the User is created
////     * or as part of a single transaction.
////     */
////    @Transactional
////    public Doctor registerDoctor(Doctor doctor) {
////        return doctorRepository.save(doctor);
////    }
////
////    /**
////     * Logic to verify a doctor (Admin only).
////     * Once verified, the doctor appears in public searches.
////     */
////    @Transactional
////    public void verifyDoctor(UUID doctorId) {
////        Doctor doctor = doctorRepository.findById(doctorId)
////                .orElseThrow(() -> new RuntimeException("Doctor not found"));
////        doctor.setVerified(true);
////        doctorRepository.save(doctor);
////    }
////
////    /**
////     * Complex Logic: Auto-generating 30-minute slots.
////     * Handles edge cases like avoiding overlapping slots and ensuring
////     * slots are created for the future only.
////     */
////    @Transactional
////    public List<Slot> generateSlots(UUID doctorId, LocalDateTime startDay, LocalDateTime endDay) {
////        Doctor doctor = doctorRepository.findById(doctorId)
////                .orElseThrow(() -> new RuntimeException("Doctor not found"));
////
////        List<Slot> newSlots = new ArrayList<>();
////        LocalDateTime current = startDay;
////
////        while (current.isBefore(endDay)) {
////            Slot slot = Slot.builder()
////                    .doctor(doctor)
////                    .startTime(current)
////                    .endTime(current.plusMinutes(30))
////                    .status(SlotStatus.AVAILABLE)
////                    .build();
////
////            newSlots.add(slot);
////            current = current.plusMinutes(30); // Increment by 30-min intervals
////        }
////
////        return slotRepository.saveAll(newSlots);
////    }
////
////    public List<Doctor> getVerifiedDoctorsByDept(UUID deptId) {
////        return doctorRepository.findByDepartmentIdAndIsVerifiedTrue(deptId);
////    }
////
////    private DoctorResponse mapToDoctorResponse(Doctor doctor) {
////        return DoctorResponse.builder()
////                .id(doctor.getId())
////                .fullName(doctor.getUser().getFirstName() + " " + doctor.getUser().getLastName())
////                .email(doctor.getUser().getEmail())
////                .specialization(doctor.getSpecialization())
////                .departmentName(doctor.getDepartment().getName())
////                .hospitalName(doctor.getHospital().getName())
////                .consultationFee(doctor.getConsultationFee())
////                .bio(doctor.getBio())
////                .isVerified(doctor.isVerified())
////                .build();
////    }
////
////    private SlotResponse mapToSlotResponse(Slot slot) {
////        return SlotResponse.builder()
////                .id(slot.getId())
////                .startTime(slot.getStartTime())
////                .endTime(slot.getEndTime())
////                .status(slot.getStatus().name())
////                .build();
////    }
////    public List<Doctor> getAllDoctors() {
////        return doctorRepository.findAll();
////    }
////}
//
//
//
//
//package com.medibot.healthcare_platform.modules.doctor.service;
//
//import com.medibot.healthcare_platform.modules.doctor.dto.DoctorResponse;
//import com.medibot.healthcare_platform.modules.doctor.dto.SlotResponse;
//import com.medibot.healthcare_platform.modules.doctor.entity.Doctor;
//import com.medibot.healthcare_platform.modules.doctor.entity.Slot;
//import com.medibot.healthcare_platform.modules.doctor.entity.SlotStatus;
//import com.medibot.healthcare_platform.modules.doctor.repository.DoctorRepository;
//import com.medibot.healthcare_platform.modules.doctor.repository.SlotRepository;
//import com.medibot.healthcare_platform.modules.hospital.repository.HospitalRepository;
//import lombok.RequiredArgsConstructor;
//import org.springframework.stereotype.Service;
//import org.springframework.transaction.annotation.Transactional;
//
//import java.time.LocalDateTime;
//import java.util.ArrayList;
//import java.util.List;
//import java.util.UUID;
//import java.util.stream.Collectors;
//
//@Service
//@RequiredArgsConstructor
//public class DoctorService {
//
//    private final DoctorRepository doctorRepository;
//    private final SlotRepository slotRepository;
//    private final HospitalRepository hospitalRepository;
//
//    // --- CREATE ---
//    @Transactional
//    public Doctor registerDoctor(Doctor doctor) {
//        return doctorRepository.save(doctor);
//    }
//
//    // --- READ (Multiple) ---
//    public List<Doctor> getAllDoctors() {
//        return doctorRepository.findAll();
//    }
//
//    public List<DoctorResponse> getAllDoctorResponses() {
//        return doctorRepository.findAll().stream()
//                .map(this::mapToDoctorResponse)
//                .collect(Collectors.toList());
//    }
//
//    public List<Doctor> getVerifiedDoctorsByDept(UUID deptId) {
//        return doctorRepository.findByDepartmentIdAndIsVerifiedTrue(deptId);
//    }
//
//    // --- READ (Single) ---
//    public Doctor getDoctorById(UUID id) {
//        return doctorRepository.findById(id)
//                .orElseThrow(() -> new RuntimeException("Doctor not found with id: " + id));
//    }
//
//    // --- UPDATE ---
//    @Transactional
//    public Doctor updateDoctor(UUID id, Doctor doctorDetails) {
//        Doctor doctor = getDoctorById(id);
//        doctor.setSpecialization(doctorDetails.getSpecialization());
//        doctor.setConsultationFee(doctorDetails.getConsultationFee());
//        doctor.setBio(doctorDetails.getBio());
//        return doctorRepository.save(doctor);
//    }
//
//    @Transactional
//    public void verifyDoctor(UUID doctorId) {
//        Doctor doctor = getDoctorById(doctorId);
//        doctor.setVerified(true);
//        doctorRepository.save(doctor);
//    }
//
//    // --- DELETE ---
//    @Transactional
//    public void deleteDoctor(UUID id) {
//        doctorRepository.deleteById(id);
//    }
//
//    // --- SLOT LOGIC ---
//    @Transactional
//    public List<Slot> generateSlots(UUID doctorId, LocalDateTime startDay, LocalDateTime endDay) {
//        Doctor doctor = getDoctorById(doctorId);
//
//        List<Slot> newSlots = new ArrayList<>();
//        LocalDateTime current = startDay;
//
//        while (current.isBefore(endDay)) {
//            Slot slot = Slot.builder()
//                    .doctor(doctor)
//                    .startTime(current)
//                    .endTime(current.plusMinutes(30))
//                    .status(SlotStatus.AVAILABLE)
//                    .build();
//
//            newSlots.add(slot);
//            current = current.plusMinutes(30);
//        }
//
//        return slotRepository.saveAll(newSlots);
//    }
//
//    // --- MAPPING HELPERS ---
//    public DoctorResponse mapToDoctorResponse(Doctor doctor) {
//        return DoctorResponse.builder()
//                .id(doctor.getId())
//                .fullName(doctor.getUser().getFirstName() + " " + doctor.getUser().getLastName())
//                .email(doctor.getUser().getEmail())
//                .specialization(doctor.getSpecialization())
//                .departmentName(doctor.getDepartment().getName())
//                .hospitalName(doctor.getHospital().getName())
//                .consultationFee(doctor.getConsultationFee())
//                .bio(doctor.getBio())
//                .isVerified(doctor.isVerified())
//                .build();
//    }
//
//    private SlotResponse mapToSlotResponse(Slot slot) {
//        return SlotResponse.builder()
//                .id(slot.getId())
//                .startTime(slot.getStartTime())
//                .endTime(slot.getEndTime())
//                .status(slot.getStatus().name())
//                .build();
//    }
//}





























package com.medibot.healthcare_platform.modules.doctor.service;

import com.medibot.healthcare_platform.modules.doctor.dto.*;
import com.medibot.healthcare_platform.modules.doctor.entity.*;
import com.medibot.healthcare_platform.modules.doctor.repository.*;
import com.medibot.healthcare_platform.modules.hospital.repository.HospitalRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.*;
import java.util.*;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class DoctorService {

    private final DoctorRepository doctorRepository;
    private final SlotRepository slotRepository;
    private final HospitalRepository hospitalRepository;
    private final DoctorSlotTemplateRepository templateRepository;
    private final DoctorAvailabilityRepository availabilityRepository;

    // ── EXISTING CRUD (unchanged) ────────────────────────────────────────────

    @Transactional
    public Doctor registerDoctor(Doctor doctor) { return doctorRepository.save(doctor); }

    public List<Doctor> getAllDoctors() { return doctorRepository.findAll(); }

    public List<DoctorResponse> getAllDoctorResponses() {
        return doctorRepository.findAll().stream()
                .map(this::mapToDoctorResponse).collect(Collectors.toList());
    }

    public List<Doctor> getVerifiedDoctorsByDept(UUID deptId) {
        return doctorRepository.findByDepartmentIdAndIsVerifiedTrue(deptId);
    }

    public Doctor getDoctorById(UUID id) {
        return doctorRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Doctor not found: " + id));
    }

    @Transactional
    public void verifyDoctor(UUID doctorId) {
        Doctor doctor = getDoctorById(doctorId);
        doctor.setVerified(true);
        doctorRepository.save(doctor);
    }

    // ── NEW: SLOT TEMPLATE MANAGEMENT ───────────────────────────────────────

    /**
     * Doctor saves their 3 session windows.
     * Called once from the Doctor Settings screen.
     * Replaces all existing templates for this doctor.
     */
    @Transactional
    public List<DoctorSlotTemplate> saveSlotTemplates(UUID doctorId, List<SlotTemplateRequest> requests) {
        Doctor doctor = getDoctorById(doctorId);
        // Clear old templates
        templateRepository.deleteByDoctorId(doctorId);

        List<DoctorSlotTemplate> templates = requests.stream().map(req ->
                DoctorSlotTemplate.builder()
                        .doctor(doctor)
                        .label(req.getLabel())
                        .startTime(req.getStartTime())
                        .endTime(req.getEndTime())
                        .build()
        ).collect(Collectors.toList());

        return templateRepository.saveAll(templates);
    }

    public List<DoctorSlotTemplate> getSlotTemplates(UUID doctorId) {
        return templateRepository.findByDoctorId(doctorId);
    }

    // ── NEW: AVAILABILITY CALENDAR MANAGEMENT ───────────────────────────────

    /**
     * Doctor marks specific dates as UNAVAILABLE.
     * All other future dates are assumed available by default.
     */
    @Transactional
    public void markUnavailableDates(UUID doctorId, List<LocalDate> unavailableDates) {
        Doctor doctor = getDoctorById(doctorId);

        for (LocalDate date : unavailableDates) {
            // Upsert: update if exists, create if not
            DoctorAvailability availability = availabilityRepository
                    .findByDoctorIdAndDate(doctorId, date)
                    .orElse(DoctorAvailability.builder().doctor(doctor).date(date).build());
            availability.setAvailable(false);
            availabilityRepository.save(availability);

            // Also delete any unbooked slots for that date
            List<Slot> slotsToRemove = slotRepository.findByDoctorIdAndDate(doctorId, date)
                    .stream()
                    .filter(s -> s.getStatus() == SlotStatus.AVAILABLE)
                    .collect(Collectors.toList());
            slotRepository.deleteAll(slotsToRemove);
        }
    }

    /**
     * Doctor marks a date back as AVAILABLE.
     * Auto-generates the 3 template slots for that date.
     */
    @Transactional
    public void markDateAvailable(UUID doctorId, LocalDate date) {
        Doctor doctor = getDoctorById(doctorId);

        DoctorAvailability availability = availabilityRepository
                .findByDoctorIdAndDate(doctorId, date)
                .orElse(DoctorAvailability.builder().doctor(doctor).date(date).build());
        availability.setAvailable(true);
        availabilityRepository.save(availability);

        // Auto-generate slots from templates
        generateSlotsForDate(doctorId, date);
    }

    /**
     * Gets a 30-day availability calendar for the patient view.
     * Returns each day with its available status and slot count.
     */
    public List<AvailabilityCalendarResponse> getCalendarForPatient(UUID doctorId, LocalDate from, LocalDate to) {
        List<DoctorAvailability> markedDays = availabilityRepository
                .findByDoctorIdAndDateBetween(doctorId, from, to);

        Map<LocalDate, DoctorAvailability> availMap = markedDays.stream()
                .collect(Collectors.toMap(DoctorAvailability::getDate, a -> a));

        List<AvailabilityCalendarResponse> calendar = new ArrayList<>();
        LocalDate cursor = from;

        while (!cursor.isAfter(to)) {
            final LocalDate day = cursor;
            boolean isAvailable = !availMap.containsKey(day) || availMap.get(day).isAvailable();
            // Don't show past dates as bookable
            if (day.isBefore(LocalDate.now())) isAvailable = false;

            List<SlotResponse> daySlots = new ArrayList<>();
            if (isAvailable) {
                daySlots = slotRepository.findAvailableSlotsByDate(doctorId, day, LocalDateTime.now())
                        .stream().map(this::mapToSlotResponse).collect(Collectors.toList());
                // If slots not yet generated but day is available, generate them
                if (daySlots.isEmpty() && !day.isBefore(LocalDate.now())) {
                    generateSlotsForDate(doctorId, day);
                    daySlots = slotRepository.findAvailableSlotsByDate(doctorId, day, LocalDateTime.now())
                            .stream().map(this::mapToSlotResponse).collect(Collectors.toList());
                }
            }

            calendar.add(AvailabilityCalendarResponse.builder()
                    .date(day)
                    .available(isAvailable && !daySlots.isEmpty())
                    .slots(daySlots)
                    .build());

            cursor = cursor.plusDays(1);
        }
        return calendar;
    }

    /**
     * Gets slots for a specific date (called when patient picks a day).
     */
    public List<SlotResponse> getAvailableSlotsForDate(UUID doctorId, LocalDate date) {
        return slotRepository.findAvailableSlotsByDate(doctorId, date, LocalDateTime.now())
                .stream().map(this::mapToSlotResponse).collect(Collectors.toList());
    }

    // ── INTERNAL HELPER ─────────────────────────────────────────────────────

    /**
     * Creates the 3 session slots for a specific date from the doctor's templates.
     * Only creates if no slots exist yet for that date.
     */
    @Transactional
    public void generateSlotsForDate(UUID doctorId, LocalDate date) {
        Doctor doctor = getDoctorById(doctorId);
        List<DoctorSlotTemplate> templates = templateRepository.findByDoctorId(doctorId);
        if (templates.isEmpty()) return;

        // Check if slots already exist for this date
        List<Slot> existing = slotRepository.findByDoctorIdAndDate(doctorId, date);
        if (!existing.isEmpty()) return;

        List<Slot> slots = templates.stream().map(template ->
                Slot.builder()
                        .doctor(doctor)
                        .date(date)
                        .template(template)
                        .startTime(LocalDateTime.of(date, template.getStartTime()))
                        .endTime(LocalDateTime.of(date, template.getEndTime()))
                        .status(SlotStatus.AVAILABLE)
                        .build()
        ).collect(Collectors.toList());

        slotRepository.saveAll(slots);
    }

    // ── MAPPING HELPERS ──────────────────────────────────────────────────────

    public DoctorResponse mapToDoctorResponse(Doctor doctor) {
        return DoctorResponse.builder()
                .id(doctor.getId())
                .fullName(doctor.getUser().getFirstName() + " " + doctor.getUser().getLastName())
                .email(doctor.getUser().getEmail())
                .specialization(doctor.getSpecialization())
                .departmentName(doctor.getDepartment().getName())
                .hospitalName(doctor.getHospital().getName())
                .consultationFee(doctor.getConsultationFee())
                .bio(doctor.getBio())
                .isVerified(doctor.isVerified())
                .build();
    }

    public SlotResponse mapToSlotResponse(Slot slot) {
        return SlotResponse.builder()
                .id(slot.getId())
                .date(slot.getDate())
                .startTime(slot.getStartTime())
                .endTime(slot.getEndTime())
                .label(slot.getTemplate() != null ? slot.getTemplate().getLabel() : "Session")
                .status(slot.getStatus().name())
                .build();
    }
}