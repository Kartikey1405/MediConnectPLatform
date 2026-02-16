//package com.medibot.healthcare_platform.modules.hospital.controller;
//
//import com.medibot.healthcare_platform.modules.hospital.dto.*;
//import com.medibot.healthcare_platform.modules.hospital.service.HospitalService;
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
//@RequestMapping("/api/admin")
//@RequiredArgsConstructor
//public class AdminHospitalController {
//
//    private final HospitalService hospitalService;
//
//    // --- Hospital Endpoints ---
//
//    @PostMapping("/hospitals")
//    @PreAuthorize("hasRole('ADMIN')")
//    public ResponseEntity<HospitalResponse> addHospital(@Valid @RequestBody HospitalRequest request) {
//        return ResponseEntity.ok(hospitalService.createHospital(request));
//    }
//
//    @GetMapping("/hospitals")
//    @PreAuthorize("hasRole('ADMIN')")
//    public ResponseEntity<List<HospitalResponse>> getAllHospitals() {
//        return ResponseEntity.ok(hospitalService.getAllHospitals());
//    }
//
//    @GetMapping("/hospitals/{id}")
//    @PreAuthorize("hasRole('ADMIN')")
//    public ResponseEntity<HospitalResponse> getHospital(@PathVariable UUID id) {
//        return ResponseEntity.ok(hospitalService.getHospitalById(id));
//    }
//
//    @PutMapping("/hospitals/{id}")
//    @PreAuthorize("hasRole('ADMIN')")
//    public ResponseEntity<HospitalResponse> updateHospital(@PathVariable UUID id, @Valid @RequestBody HospitalRequest request) {
//        return ResponseEntity.ok(hospitalService.updateHospital(id, request));
//    }
//
//    @DeleteMapping("/hospitals/{id}")
//    @PreAuthorize("hasRole('ADMIN')")
//    public ResponseEntity<String> deleteHospital(@PathVariable UUID id) {
//        hospitalService.deleteHospital(id);
//        return ResponseEntity.ok("Hospital deleted successfully");
//    }
//
//    // --- Department Endpoints ---
//
//    @PostMapping("/departments")
//    @PreAuthorize("hasRole('ADMIN')")
//    public ResponseEntity<DepartmentResponse> addDepartment(@Valid @RequestBody DepartmentRequest request) {
//        return ResponseEntity.ok(hospitalService.addDepartmentToHospital(request));
//    }
//
//    @GetMapping("/hospitals/{id}/departments")
//    @PreAuthorize("hasRole('ADMIN')")
//    public ResponseEntity<List<DepartmentResponse>> getHospitalDepartments(@PathVariable UUID id) {
//        return ResponseEntity.ok(hospitalService.getDepartmentsByHospital(id));
//    }
//
//    @DeleteMapping("/departments/{id}")
//    @PreAuthorize("hasRole('ADMIN')")
//    public ResponseEntity<String> deleteDepartment(@PathVariable UUID id) {
//        hospitalService.deleteDepartment(id);
//        return ResponseEntity.ok("Department deleted successfully");
//    }
//}



package com.medibot.healthcare_platform.modules.hospital.controller;

import com.medibot.healthcare_platform.modules.hospital.dto.*;
import com.medibot.healthcare_platform.modules.hospital.service.HospitalService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus; // Use for more descriptive responses
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/admin")
@RequiredArgsConstructor
@PreAuthorize("hasRole('ADMIN')") // Apply class-level security to keep code clean
public class AdminHospitalController {

    private final HospitalService hospitalService;

    // --- Hospital Management ---

    @PostMapping("/hospitals")
    public ResponseEntity<HospitalResponse> addHospital(@Valid @RequestBody HospitalRequest request) {
        // Return 201 Created for new resources
        return new ResponseEntity<>(hospitalService.createHospital(request), HttpStatus.CREATED);
    }

    @GetMapping("/hospitals")
    public ResponseEntity<List<HospitalResponse>> getAllHospitals() {
        return ResponseEntity.ok(hospitalService.getAllHospitals());
    }

    @GetMapping("/hospitals/{id}")
    public ResponseEntity<HospitalResponse> getHospital(@PathVariable UUID id) {
        return ResponseEntity.ok(hospitalService.getHospitalById(id));
    }

    @PutMapping("/hospitals/{id}")
    public ResponseEntity<HospitalResponse> updateHospital(@PathVariable UUID id, @Valid @RequestBody HospitalRequest request) {
        return ResponseEntity.ok(hospitalService.updateHospital(id, request));
    }

    @DeleteMapping("/hospitals/{id}")
    public ResponseEntity<Void> deleteHospital(@PathVariable UUID id) {
        hospitalService.deleteHospital(id);
        // Standard practice for successful deletion is 204 No Content
        return ResponseEntity.noContent().build();
    }

    // --- Department Management ---

    @PostMapping("/departments")
    public ResponseEntity<DepartmentResponse> addDepartment(@Valid @RequestBody DepartmentRequest request) {
        return new ResponseEntity<>(hospitalService.addDepartmentToHospital(request), HttpStatus.CREATED);
    }

    @GetMapping("/hospitals/{id}/departments")
    public ResponseEntity<List<DepartmentResponse>> getHospitalDepartments(@PathVariable UUID id) {
        return ResponseEntity.ok(hospitalService.getDepartmentsByHospital(id));
    }

    @DeleteMapping("/departments/{id}")
    public ResponseEntity<Void> deleteDepartment(@PathVariable UUID id) {
        hospitalService.deleteDepartment(id);
        return ResponseEntity.noContent().build();
    }
}