//package com.medibot.healthcare_platform.modules.records.controller;
//
//import com.medibot.healthcare_platform.modules.records.dto.MedicalRecordRequest;
//import com.medibot.healthcare_platform.modules.records.dto.MedicalRecordResponse;
//import com.medibot.healthcare_platform.modules.records.service.RecordService;
//import lombok.RequiredArgsConstructor;
//import org.springframework.http.ResponseEntity;
//import org.springframework.security.access.prepost.PreAuthorize;
//import org.springframework.web.bind.annotation.*;
//
//import java.util.List;
//import java.util.UUID;
//
//@RestController
//@RequestMapping("/api/records")
//@RequiredArgsConstructor
//public class RecordController {
//
//    private final RecordService recordService;
//
//    /**
//     * Doctors use this to save a new diagnosis and prescription.
//     * Accessible only to users with the 'DOCTOR' role.
//     */
//    @PostMapping("/doctor/{doctorId}/patient/{patientId}")
//    @PreAuthorize("hasRole('DOCTOR')")
//    public ResponseEntity<MedicalRecordResponse> createRecord(
//            @PathVariable UUID doctorId,
//            @PathVariable UUID patientId,
//            @RequestBody MedicalRecordRequest request) {
//        return ResponseEntity.ok(recordService.createRecord(patientId, doctorId, request));
//    }
//
//    /**
//     * Patients view their own medical history.
//     * Accessible to the patient themselves or an ADMIN.
//     */
//    @GetMapping("/patient/{patientId}")
//    @PreAuthorize("hasRole('PATIENT') or hasRole('ADMIN')")
//    public ResponseEntity<List<MedicalRecordResponse>> getMyHistory(@PathVariable UUID patientId) {
//        return ResponseEntity.ok(recordService.getPatientHistory(patientId));
//    }
//
//    /**
//     * Doctors can view the history of a specific patient during consultation.
//     */
//    @GetMapping("/doctor/view/patient/{patientId}")
//    @PreAuthorize("hasRole('DOCTOR')")
//    public ResponseEntity<List<MedicalRecordResponse>> getPatientHistoryForDoctor(@PathVariable UUID patientId) {
//        return ResponseEntity.ok(recordService.getPatientHistory(patientId));
//    }
//
//
//    // Add to RecordController.java
//    @PostMapping("/patient/{patientId}/save-triage")
//    @PreAuthorize("hasRole('PATIENT')")
//    public ResponseEntity<MedicalRecordResponse> saveTriage(
//            @PathVariable UUID patientId,
//            @RequestParam String disease,
//            @RequestParam String symptoms,
//            @RequestBody List<String> tips) {
//        return ResponseEntity.ok(recordService.saveTriageResult(patientId, disease, symptoms, tips));
//    }
//}




package com.medibot.healthcare_platform.modules.records.controller;

import com.medibot.healthcare_platform.modules.records.dto.MedicalRecordRequest;
import com.medibot.healthcare_platform.modules.records.dto.MedicalRecordResponse;
import com.medibot.healthcare_platform.modules.records.service.RecordService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/records")
@RequiredArgsConstructor
public class RecordController {

    private final RecordService recordService;

    /**
     * Doctors use this to save a new diagnosis and prescription during consultation.
     */
    @PostMapping("/doctor/{doctorId}/patient/{patientId}")
    @PreAuthorize("hasRole('DOCTOR')")
    public ResponseEntity<MedicalRecordResponse> createRecord(
            @PathVariable UUID doctorId,
            @PathVariable UUID patientId,
            @RequestBody MedicalRecordRequest request) {
        return ResponseEntity.ok(recordService.createRecord(patientId, doctorId, request));
    }

    /**
     * Patients view their own medical history (Reports + Consultations).
     */
    @GetMapping("/patient/{patientId}")
    @PreAuthorize("hasRole('PATIENT') or hasRole('ADMIN')")
    public ResponseEntity<List<MedicalRecordResponse>> getMyHistory(@PathVariable UUID patientId) {
        return ResponseEntity.ok(recordService.getPatientHistory(patientId));
    }

    /**
     * Doctors can view the history of a specific patient during consultation.
     */
    @GetMapping("/doctor/view/patient/{patientId}")
    @PreAuthorize("hasRole('DOCTOR')")
    public ResponseEntity<List<MedicalRecordResponse>> getPatientHistoryForDoctor(@PathVariable UUID patientId) {
        return ResponseEntity.ok(recordService.getPatientHistory(patientId));
    }

    /**
     * NEW: Physical Report Upload to Cloudinary.
     * Use this for Blood Tests, X-rays, etc.
     */
    @PostMapping("/upload/{patientId}")
    @PreAuthorize("hasRole('PATIENT')")
    public ResponseEntity<MedicalRecordResponse> uploadReport(
            @PathVariable UUID patientId,
            @RequestParam("title") String title,
            @RequestParam("file") MultipartFile file) throws IOException {
        return ResponseEntity.ok(recordService.uploadReport(patientId, title, file));
    }
}