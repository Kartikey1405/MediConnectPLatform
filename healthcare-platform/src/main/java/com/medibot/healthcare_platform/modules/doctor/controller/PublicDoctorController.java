////package com.medibot.healthcare_platform.modules.doctor.controller;
////
////import com.medibot.healthcare_platform.modules.doctor.entity.Doctor;
////import com.medibot.healthcare_platform.modules.doctor.entity.Slot;
////import com.medibot.healthcare_platform.modules.doctor.service.DoctorService;
////import com.medibot.healthcare_platform.modules.doctor.repository.SlotRepository;
////import lombok.RequiredArgsConstructor;
////import org.springframework.http.ResponseEntity;
////import org.springframework.web.bind.annotation.*;
////
////import java.time.LocalDateTime;
////import java.util.List;
////import java.util.UUID;
////
////@RestController
////@RequestMapping("/api/public/doctors")
////@RequiredArgsConstructor
////public class PublicDoctorController {
////
////    private final DoctorService doctorService;
////    private final SlotRepository slotRepository;
////
////    @GetMapping("/department/{deptId}")
////    public ResponseEntity<List<Doctor>> getDoctorsByDepartment(@PathVariable UUID deptId) {
////        return ResponseEntity.ok(doctorService.getVerifiedDoctorsByDept(deptId));
////    }
////
////    @GetMapping("/{doctorId}/available-slots")
////    public ResponseEntity<List<Slot>> getAvailableSlots(@PathVariable UUID doctorId) {
////        // Uses the custom query we wrote in SlotRepository
////        return ResponseEntity.ok(slotRepository.findAvailableSlots(doctorId, LocalDateTime.now()));
////    }
////}
//
//
//package com.medibot.healthcare_platform.modules.doctor.controller;
//
//import com.medibot.healthcare_platform.modules.doctor.dto.DoctorResponse;
//import com.medibot.healthcare_platform.modules.doctor.dto.SlotResponse;
//import com.medibot.healthcare_platform.modules.doctor.service.DoctorService;
//import com.medibot.healthcare_platform.modules.doctor.repository.SlotRepository;
//import lombok.RequiredArgsConstructor;
//import org.springframework.http.ResponseEntity;
//import org.springframework.web.bind.annotation.*;
//
//import java.time.LocalDateTime;
//import java.util.List;
//import java.util.UUID;
//import java.util.stream.Collectors;
//
//@RestController
//@RequestMapping("/api/public/doctors")
//@RequiredArgsConstructor
//public class PublicDoctorController {
//
//    private final DoctorService doctorService;
//    private final SlotRepository slotRepository;
//
//    /**
//     * Finds verified doctors by department.
//     * Essential for AI Disease -> Department -> Doctor mapping.
//     */
//    @GetMapping("/department/{deptId}")
//    public ResponseEntity<List<DoctorResponse>> getDoctorsByDepartment(@PathVariable UUID deptId) {
//        List<DoctorResponse> responses = doctorService.getVerifiedDoctorsByDept(deptId)
//                .stream()
//                .map(doctor -> DoctorResponse.builder()
//                        .id(doctor.getId())
//                        .fullName(doctor.getUser().getFirstName() + " " + doctor.getUser().getLastName())
//                        .email(doctor.getUser().getEmail())
//                        .specialization(doctor.getSpecialization())
//                        .departmentName(doctor.getDepartment().getName())
//                        .hospitalName(doctor.getHospital().getName())
//                        .consultationFee(doctor.getConsultationFee())
//                        .bio(doctor.getBio())
//                        .isVerified(doctor.isVerified())
//                        .build())
//                .collect(Collectors.toList());
//
//        return ResponseEntity.ok(responses);
//    }
//
//    /**
//     * Gets available slots for a doctor.
//     * Filters out occupied or expired slots.
//     */
//    @GetMapping("/{doctorId}/available-slots")
//    public ResponseEntity<List<SlotResponse>> getAvailableSlots(@PathVariable UUID doctorId) {
//        List<SlotResponse> responses = slotRepository.findAvailableSlots(doctorId, LocalDateTime.now())
//                .stream()
//                .map(slot -> SlotResponse.builder()
//                        .id(slot.getId())
//                        .startTime(slot.getStartTime())
//                        .endTime(slot.getEndTime())
//                        .status(slot.getStatus().name())
//                        .build())
//                .collect(Collectors.toList());
//
//        return ResponseEntity.ok(responses);
//    }
//}


package com.medibot.healthcare_platform.modules.doctor.controller;

import com.medibot.healthcare_platform.modules.doctor.dto.DoctorResponse;
import com.medibot.healthcare_platform.modules.doctor.dto.SlotResponse;
import com.medibot.healthcare_platform.modules.doctor.service.DoctorService;
import com.medibot.healthcare_platform.modules.doctor.repository.SlotRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/public/doctors")
@RequiredArgsConstructor
public class PublicDoctorController {

    private final DoctorService doctorService;
    private final SlotRepository slotRepository;

    /**
     * NEW METHOD: Fixes the 404 Not Found error.
     * Fetches all verified doctors for the general booking view.
     */
    @GetMapping("/all")
    public ResponseEntity<List<DoctorResponse>> getAllDoctors() {
        List<DoctorResponse> responses = doctorService.getAllDoctors()
                .stream()
                .filter(doctor -> doctor.isVerified()) // Safety check: only verified doctors
                .map(doctor -> doctorService.mapToDoctorResponse(doctor)) // Uses helper from your DoctorService
                .collect(Collectors.toList());

        return ResponseEntity.ok(responses);
    }

    /**
     * Finds verified doctors by department.
     * Used by the "Book Specialist" button in the AI Triage chat.
     */
    @GetMapping("/department/{deptId}")
    public ResponseEntity<List<DoctorResponse>> getDoctorsByDepartment(@PathVariable UUID deptId) {
        List<DoctorResponse> responses = doctorService.getVerifiedDoctorsByDept(deptId)
                .stream()
                .map(doctor -> doctorService.mapToDoctorResponse(doctor))
                .collect(Collectors.toList());

        return ResponseEntity.ok(responses);
    }

    /**
     * Gets available slots for a doctor.
     */
    @GetMapping("/{doctorId}/available-slots")
    public ResponseEntity<List<SlotResponse>> getAvailableSlots(@PathVariable UUID doctorId) {
        List<SlotResponse> responses = slotRepository.findAvailableSlots(doctorId, LocalDateTime.now())
                .stream()
                .map(slot -> SlotResponse.builder()
                        .id(slot.getId())
                        .startTime(slot.getStartTime())
                        .endTime(slot.getEndTime())
                        .status(slot.getStatus().name())
                        .build())
                .collect(Collectors.toList());

        return ResponseEntity.ok(responses);
    }
}