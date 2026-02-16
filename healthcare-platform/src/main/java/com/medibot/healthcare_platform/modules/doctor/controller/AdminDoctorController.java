////package com.medibot.healthcare_platform.modules.doctor.controller;
////
////import com.medibot.healthcare_platform.modules.doctor.dto.DoctorRegistrationRequest;
////import com.medibot.healthcare_platform.modules.doctor.dto.DoctorResponse;
////import com.medibot.healthcare_platform.modules.doctor.entity.Doctor;
////import com.medibot.healthcare_platform.modules.doctor.service.DoctorService;
////import com.medibot.healthcare_platform.modules.hospital.entity.Department;
////import com.medibot.healthcare_platform.modules.hospital.entity.Hospital;
////import com.medibot.healthcare_platform.modules.identity.entity.User;
////import jakarta.validation.Valid;
////import lombok.RequiredArgsConstructor;
////import org.springframework.http.ResponseEntity;
////import org.springframework.security.access.prepost.PreAuthorize;
////import org.springframework.web.bind.annotation.*;
////
////import java.util.List;
////import java.util.UUID;
////
////@RestController
////@RequestMapping("/api/admin/doctors")
////@RequiredArgsConstructor
////public class AdminDoctorController {
////
////    private final DoctorService doctorService;
////
////    @GetMapping
////    @PreAuthorize("hasRole('ADMIN')")
////    public ResponseEntity<List<Doctor>> getAllDoctors() {
////        // We'll use the inherited findAll from JpaRepository via Service
////        return ResponseEntity.ok(doctorService.getAllDoctors());
////    }
////
////    @PatchMapping("/{id}/verify")
////    @PreAuthorize("hasRole('ADMIN')")
////    public ResponseEntity<String> verifyDoctor(@PathVariable UUID id) {
////        doctorService.verifyDoctor(id);
////        return ResponseEntity.ok("Doctor verified successfully. They are now visible to patients.");
////    }
////
////    @PostMapping("/register")
////    @PreAuthorize("hasRole('ADMIN')")
////    public ResponseEntity<DoctorResponse> registerDoctor(@Valid @RequestBody DoctorRegistrationRequest request) {
////        // 1. Fetch the existing User, Hospital, and Department
////        User user = userService.getRawUserById(request.getUserId());
////        Hospital hospital = hospitalService.getRawHospitalById(request.getHospitalId());
////        Department dept = hospitalService.getRawDepartmentById(request.getDepartmentId());
////
////        // 2. Build the Doctor entity
////        Doctor doctor = Doctor.builder()
////                .user(user)
////                .hospital(hospital)
////                .department(dept)
////                .specialization(request.getSpecialization())
////                .consultationFee(request.getConsultationFee())
////                .bio(request.getBio())
////                .isVerified(false) // Needs separate verification step
////                .build();
////
////        return ResponseEntity.ok(doctorService.mapToDoctorResponse(doctorService.registerDoctor(doctor)));
////    }
////}
//
//package com.medibot.healthcare_platform.modules.doctor.controller;
//
//import com.medibot.healthcare_platform.modules.doctor.dto.DoctorRegistrationRequest;
//import com.medibot.healthcare_platform.modules.doctor.dto.DoctorResponse;
//import com.medibot.healthcare_platform.modules.doctor.entity.Doctor;
//import com.medibot.healthcare_platform.modules.doctor.service.DoctorService;
//import com.medibot.healthcare_platform.modules.hospital.entity.Department;
//import com.medibot.healthcare_platform.modules.hospital.entity.Hospital;
//import com.medibot.healthcare_platform.modules.hospital.service.HospitalService;
//import com.medibot.healthcare_platform.modules.identity.entity.User;
//import com.medibot.healthcare_platform.modules.identity.service.UserService;
//import jakarta.validation.Valid;
//import lombok.RequiredArgsConstructor;
//import org.springframework.http.ResponseEntity;
//import org.springframework.security.access.prepost.PreAuthorize;
//import org.springframework.web.bind.annotation.*;
//
//import java.util.List;
//import java.util.UUID;
//
//@RestController
//@RequestMapping("/api/admin/doctors")
//@RequiredArgsConstructor
//@PreAuthorize("hasRole('ADMIN')") // Apply class-level security to all endpoints
//public class AdminDoctorController {
//
//    private final DoctorService doctorService;
//    private final UserService userService; // Added for User lookup
//    private final HospitalService hospitalService; // Added for Hospital/Dept lookup
//
//    @GetMapping
//    public ResponseEntity<List<Doctor>> getAllDoctors() {
//        return ResponseEntity.ok(doctorService.getAllDoctors());
//    }
//
//    @PatchMapping("/{id}/verify")
//    public ResponseEntity<String> verifyDoctor(@PathVariable UUID id) {
//        doctorService.verifyDoctor(id);
//        return ResponseEntity.ok("Doctor verified successfully. They are now visible to patients.");
//    }
//
//    @PostMapping("/register")
//    public ResponseEntity<DoctorResponse> registerDoctor(@Valid @RequestBody DoctorRegistrationRequest request) {
//        // 1. Fetch the existing User, Hospital, and Department from their respective services
//        // Ensure you have implemented getRawUserById in UserService and the others in HospitalService
//        User user = userService.getRawUserById(request.getUserId());
//        Hospital hospital = hospitalService.getRawHospitalById(request.getHospitalId());
//        Department dept = hospitalService.getRawDepartmentById(request.getDepartmentId());
//
//        // 2. Build the Doctor entity
//        Doctor doctor = Doctor.builder()
//                .user(user)
//                .hospital(hospital)
//                .department(dept)
//                .specialization(request.getSpecialization())
//                .consultationFee(request.getConsultationFee())
//                .bio(request.getBio())
//                .isVerified(false) // Verification is a separate Admin step
//                .build();
//
//        // 3. Save and map to response
//        Doctor savedDoctor = doctorService.registerDoctor(doctor);
//        return ResponseEntity.ok(doctorService.mapToDoctorResponse(savedDoctor));
//    }
//}






package com.medibot.healthcare_platform.modules.doctor.controller;

import com.medibot.healthcare_platform.modules.doctor.dto.DoctorRegistrationRequest;
import com.medibot.healthcare_platform.modules.doctor.dto.DoctorResponse;
import com.medibot.healthcare_platform.modules.doctor.entity.Doctor;
import com.medibot.healthcare_platform.modules.doctor.service.DoctorService;
import com.medibot.healthcare_platform.modules.hospital.entity.Department;
import com.medibot.healthcare_platform.modules.hospital.entity.Hospital;
import com.medibot.healthcare_platform.modules.hospital.service.HospitalService;
import com.medibot.healthcare_platform.modules.identity.entity.User;
import com.medibot.healthcare_platform.modules.identity.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/admin/doctors")
@RequiredArgsConstructor
@PreAuthorize("hasRole('ADMIN')")
public class AdminDoctorController {

    private final DoctorService doctorService;
    private final UserService userService;
    private final HospitalService hospitalService;

    /**
     * FIX: Returns DoctorResponse instead of Doctor to prevent JSON recursion crash.
     * This ensures the frontend receives a clean array for the .filter() function.
     */
    @GetMapping
    public ResponseEntity<List<DoctorResponse>> getAllDoctors() {
        // Uses the mapping logic in your service to return flattened DTOs
        return ResponseEntity.ok(doctorService.getAllDoctorResponses());
    }

    @PatchMapping("/{id}/verify")
    public ResponseEntity<String> verifyDoctor(@PathVariable UUID id) {
        doctorService.verifyDoctor(id);
        return ResponseEntity.ok("Doctor verified successfully.");
    }

    @PostMapping("/register")
    public ResponseEntity<DoctorResponse> registerDoctor(@Valid @RequestBody DoctorRegistrationRequest request) {
        // 1. Fetch related entities
        User user = userService.getRawUserById(request.getUserId());
        Hospital hospital = hospitalService.getRawHospitalById(request.getHospitalId());
        Department dept = hospitalService.getRawDepartmentById(request.getDepartmentId());

        // 2. Build entity
        Doctor doctor = Doctor.builder()
                .user(user)
                .hospital(hospital)
                .department(dept)
                .specialization(request.getSpecialization())
                .consultationFee(request.getConsultationFee())
                .bio(request.getBio())
                .isVerified(false)
                .build();

        // 3. Persist and return flattened DTO
        Doctor savedDoctor = doctorService.registerDoctor(doctor);
        return ResponseEntity.ok(doctorService.mapToDoctorResponse(savedDoctor));
    }
}