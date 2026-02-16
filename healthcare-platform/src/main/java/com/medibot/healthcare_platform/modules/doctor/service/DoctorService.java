//package com.medibot.healthcare_platform.modules.doctor.service;
//
//import com.medibot.healthcare_platform.modules.doctor.dto.DoctorResponse;
//import com.medibot.healthcare_platform.modules.doctor.dto.SlotResponse;
//import com.medibot.healthcare_platform.modules.doctor.entity.Doctor;
//import com.medibot.healthcare_platform.modules.doctor.entity.Slot;
//import com.medibot.healthcare_platform.modules.doctor.entity.SlotStatus;
//import com.medibot.healthcare_platform.modules.doctor.repository.DoctorRepository;
//import com.medibot.healthcare_platform.modules.doctor.repository.SlotRepository;
//import com.medibot.healthcare_platform.modules.hospital.entity.Hospital;
//import com.medibot.healthcare_platform.modules.hospital.repository.HospitalRepository;
//import lombok.RequiredArgsConstructor;
//import org.springframework.stereotype.Service;
//import org.springframework.transaction.annotation.Transactional;
//
//import java.time.LocalDateTime;
//import java.util.ArrayList;
//import java.util.List;
//import java.util.UUID;
//
//@Service
//@RequiredArgsConstructor
//public class DoctorService {
//
//    private final DoctorRepository doctorRepository;
//    private final SlotRepository slotRepository;
//    private final HospitalRepository hospitalRepository;
//
//    /**
//     * Completes the Doctor onboarding.
//     * In production, this would be called after the User is created
//     * or as part of a single transaction.
//     */
//    @Transactional
//    public Doctor registerDoctor(Doctor doctor) {
//        return doctorRepository.save(doctor);
//    }
//
//    /**
//     * Logic to verify a doctor (Admin only).
//     * Once verified, the doctor appears in public searches.
//     */
//    @Transactional
//    public void verifyDoctor(UUID doctorId) {
//        Doctor doctor = doctorRepository.findById(doctorId)
//                .orElseThrow(() -> new RuntimeException("Doctor not found"));
//        doctor.setVerified(true);
//        doctorRepository.save(doctor);
//    }
//
//    /**
//     * Complex Logic: Auto-generating 30-minute slots.
//     * Handles edge cases like avoiding overlapping slots and ensuring
//     * slots are created for the future only.
//     */
//    @Transactional
//    public List<Slot> generateSlots(UUID doctorId, LocalDateTime startDay, LocalDateTime endDay) {
//        Doctor doctor = doctorRepository.findById(doctorId)
//                .orElseThrow(() -> new RuntimeException("Doctor not found"));
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
//            current = current.plusMinutes(30); // Increment by 30-min intervals
//        }
//
//        return slotRepository.saveAll(newSlots);
//    }
//
//    public List<Doctor> getVerifiedDoctorsByDept(UUID deptId) {
//        return doctorRepository.findByDepartmentIdAndIsVerifiedTrue(deptId);
//    }
//
//    private DoctorResponse mapToDoctorResponse(Doctor doctor) {
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
//    public List<Doctor> getAllDoctors() {
//        return doctorRepository.findAll();
//    }
//}




package com.medibot.healthcare_platform.modules.doctor.service;

import com.medibot.healthcare_platform.modules.doctor.dto.DoctorResponse;
import com.medibot.healthcare_platform.modules.doctor.dto.SlotResponse;
import com.medibot.healthcare_platform.modules.doctor.entity.Doctor;
import com.medibot.healthcare_platform.modules.doctor.entity.Slot;
import com.medibot.healthcare_platform.modules.doctor.entity.SlotStatus;
import com.medibot.healthcare_platform.modules.doctor.repository.DoctorRepository;
import com.medibot.healthcare_platform.modules.doctor.repository.SlotRepository;
import com.medibot.healthcare_platform.modules.hospital.repository.HospitalRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class DoctorService {

    private final DoctorRepository doctorRepository;
    private final SlotRepository slotRepository;
    private final HospitalRepository hospitalRepository;

    // --- CREATE ---
    @Transactional
    public Doctor registerDoctor(Doctor doctor) {
        return doctorRepository.save(doctor);
    }

    // --- READ (Multiple) ---
    public List<Doctor> getAllDoctors() {
        return doctorRepository.findAll();
    }

    public List<DoctorResponse> getAllDoctorResponses() {
        return doctorRepository.findAll().stream()
                .map(this::mapToDoctorResponse)
                .collect(Collectors.toList());
    }

    public List<Doctor> getVerifiedDoctorsByDept(UUID deptId) {
        return doctorRepository.findByDepartmentIdAndIsVerifiedTrue(deptId);
    }

    // --- READ (Single) ---
    public Doctor getDoctorById(UUID id) {
        return doctorRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Doctor not found with id: " + id));
    }

    // --- UPDATE ---
    @Transactional
    public Doctor updateDoctor(UUID id, Doctor doctorDetails) {
        Doctor doctor = getDoctorById(id);
        doctor.setSpecialization(doctorDetails.getSpecialization());
        doctor.setConsultationFee(doctorDetails.getConsultationFee());
        doctor.setBio(doctorDetails.getBio());
        return doctorRepository.save(doctor);
    }

    @Transactional
    public void verifyDoctor(UUID doctorId) {
        Doctor doctor = getDoctorById(doctorId);
        doctor.setVerified(true);
        doctorRepository.save(doctor);
    }

    // --- DELETE ---
    @Transactional
    public void deleteDoctor(UUID id) {
        doctorRepository.deleteById(id);
    }

    // --- SLOT LOGIC ---
    @Transactional
    public List<Slot> generateSlots(UUID doctorId, LocalDateTime startDay, LocalDateTime endDay) {
        Doctor doctor = getDoctorById(doctorId);

        List<Slot> newSlots = new ArrayList<>();
        LocalDateTime current = startDay;

        while (current.isBefore(endDay)) {
            Slot slot = Slot.builder()
                    .doctor(doctor)
                    .startTime(current)
                    .endTime(current.plusMinutes(30))
                    .status(SlotStatus.AVAILABLE)
                    .build();

            newSlots.add(slot);
            current = current.plusMinutes(30);
        }

        return slotRepository.saveAll(newSlots);
    }

    // --- MAPPING HELPERS ---
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

    private SlotResponse mapToSlotResponse(Slot slot) {
        return SlotResponse.builder()
                .id(slot.getId())
                .startTime(slot.getStartTime())
                .endTime(slot.getEndTime())
                .status(slot.getStatus().name())
                .build();
    }
}