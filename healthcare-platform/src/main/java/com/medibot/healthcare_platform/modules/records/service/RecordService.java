//package com.medibot.healthcare_platform.modules.records.service;
//
//import com.medibot.healthcare_platform.modules.doctor.entity.Doctor;
//import com.medibot.healthcare_platform.modules.doctor.repository.DoctorRepository;
//import com.medibot.healthcare_platform.modules.identity.entity.User;
//import com.medibot.healthcare_platform.modules.identity.repository.UserRepository;
//import com.medibot.healthcare_platform.modules.records.entity.*;
//import com.medibot.healthcare_platform.modules.records.repository.*;
//import com.medibot.healthcare_platform.modules.records.dto.*;
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
//public class RecordService {
//
//    // These MUST be declared as final for @RequiredArgsConstructor to inject them
//    private final MedicalRecordRepository recordRepository;
//    private final PrescriptionRepository prescriptionRepository;
//    private final UserRepository userRepository;
//    private final DoctorRepository doctorRepository;
//
//    public List<MedicalRecordResponse> getPatientHistory(UUID patientId) {
//        return recordRepository.findByPatientIdOrderByCreatedAtDesc(patientId).stream()
//                .map(this::mapToResponse)
//                .collect(Collectors.toList());
//    }
//
//    @Transactional
//    public MedicalRecordResponse createRecord(UUID patientId, UUID doctorId, MedicalRecordRequest request) {
//        // Now these repositories will be recognized by the compiler
//        User patient = userRepository.findById(patientId)
//                .orElseThrow(() -> new RuntimeException("Patient not found"));
//        Doctor doctor = doctorRepository.findById(doctorId)
//                .orElseThrow(() -> new RuntimeException("Doctor not found"));
//
//        MedicalRecord record = MedicalRecord.builder()
//                .patient(patient)
//                .doctor(doctor)
//                .diagnosis(request.getDiagnosis())
//                .symptoms(request.getSymptoms())
//                .build();
//
//        MedicalRecord savedRecord = recordRepository.save(record);
//
//        if (request.getPrescriptions() != null && !request.getPrescriptions().isEmpty()) {
//            List<Prescription> prescriptions = request.getPrescriptions().stream()
//                    .map(p -> Prescription.builder()
//                            .medicalRecord(savedRecord)
//                            .medicineName(p.getMedicineName())
//                            .dosage(p.getDosage())
//                            .frequency(p.getFrequency())
//                            .instructions(p.getInstructions())
//                            .build())
//                    .collect(Collectors.toList());
//
//            prescriptionRepository.saveAll(prescriptions);
//            savedRecord.setPrescriptions(prescriptions);
//        }
//
//        return mapToResponse(savedRecord);
//    }
//
//
//    // Add to RecordService.java
//    @Transactional
//    public MedicalRecordResponse saveTriageResult(UUID patientId, String disease, String symptoms, List<String> tips) {
//        User patient = userRepository.findById(patientId)
//                .orElseThrow(() -> new RuntimeException("Patient not found"));
//
//        // Combine AI tips into a string for the record description
//        String diagnosisDescription = disease + "\n\nAI Advice:\n" + String.join(", ", tips);
//
//        MedicalRecord record = MedicalRecord.builder()
//                .patient(patient)
//                .doctor(null) // Patient-saved records don't have a doctor yet
//                .diagnosis(diagnosisDescription)
//                .symptoms(symptoms)
//                .build();
//
//        return mapToResponse(recordRepository.save(record));
//    }
//
//    // Inside com.medibot.healthcare_platform.modules.records.service.RecordService
//    private MedicalRecordResponse mapToResponse(MedicalRecord record) {
//        // FIX: Check if doctor is null before accessing user data
//        String docName = "AI Triage System";
//        if (record.getDoctor() != null && record.getDoctor().getUser() != null) {
//            docName = record.getDoctor().getUser().getFirstName() + " " + record.getDoctor().getUser().getLastName();
//        }
//
//        return MedicalRecordResponse.builder()
//                .id(record.getId())
//                .doctorName(docName)
//                .diagnosis(record.getDiagnosis())
//                .symptoms(record.getSymptoms())
//                .date(record.getCreatedAt())
//                .prescriptions(record.getPrescriptions() != null ?
//                        record.getPrescriptions().stream()
//                                .map(p -> PrescriptionDTO.builder()
//                                        .medicineName(p.getMedicineName())
//                                        .dosage(p.getDosage())
//                                        .frequency(p.getFrequency())
//                                        .instructions(p.getInstructions())
//                                        .build())
//                                .collect(Collectors.toList()) : List.of())
//                .build();
//    }
//}



//package com.medibot.healthcare_platform.modules.records.service;
//
//import com.medibot.healthcare_platform.modules.consultation.repository.ConsultationPrescriptionRepository;
//import com.medibot.healthcare_platform.modules.doctor.entity.Doctor;
//import com.medibot.healthcare_platform.modules.doctor.repository.DoctorRepository;
//import com.medibot.healthcare_platform.modules.identity.entity.User;
//import com.medibot.healthcare_platform.modules.identity.repository.UserRepository;
//import com.medibot.healthcare_platform.modules.records.entity.*;
//import com.medibot.healthcare_platform.modules.records.repository.*;
//import com.medibot.healthcare_platform.modules.records.dto.*;
//import lombok.RequiredArgsConstructor;
//import org.springframework.stereotype.Service;
//import org.springframework.transaction.annotation.Transactional;
//import org.springframework.web.multipart.MultipartFile;
//
//import java.io.IOException;
//import java.util.List;
//import java.util.UUID;
//import java.util.stream.Collectors;
//
//@Service
//@RequiredArgsConstructor
//public class RecordService {
//
//    private final MedicalRecordRepository recordRepository;
//    private final ConsultationPrescriptionRepository prescriptionRepository;
//    private final UserRepository userRepository;
//    private final DoctorRepository doctorRepository;
//    private final FileStorageService fileStorageService; // Cloudinary Service injected here
//
//    /**
//     * Retrieves all records (consultations and uploaded reports) for a patient.
//     */
//    public List<MedicalRecordResponse> getPatientHistory(UUID patientId) {
//        return recordRepository.findByPatientIdOrderByCreatedAtDesc(patientId).stream()
//                .map(this::mapToResponse)
//                .collect(Collectors.toList());
//    }
//
//    /**
//     * Handles creation of records by doctors (Prescriptions/Diagnosis).
//     */
//    @Transactional
//    public MedicalRecordResponse createRecord(UUID patientId, UUID doctorId, MedicalRecordRequest request) {
//        User patient = userRepository.findById(patientId)
//                .orElseThrow(() -> new RuntimeException("Patient not found"));
//        Doctor doctor = doctorRepository.findById(doctorId)
//                .orElseThrow(() -> new RuntimeException("Doctor not found"));
//
//        MedicalRecord record = MedicalRecord.builder()
//                .patient(patient)
//                .doctor(doctor)
//                .title("Consultation Record")
//                .diagnosis(request.getDiagnosis())
//                .symptoms(request.getSymptoms())
//                .build();
//
//        MedicalRecord savedRecord = recordRepository.save(record);
//
//        if (request.getPrescriptions() != null && !request.getPrescriptions().isEmpty()) {
//            List<Prescription> prescriptions = request.getPrescriptions().stream()
//                    .map(p -> Prescription.builder()
//                            .medicalRecord(savedRecord)
//                            .medicineName(p.getMedicineName())
//                            .dosage(p.getDosage())
//                            .frequency(p.getFrequency())
//                            .duration(p.getDuration())
//                            .instructions(p.getInstructions())
//                            .build())
//                    .collect(Collectors.toList());
//
//            prescriptionRepository.saveAll(prescriptions);
//            savedRecord.setPrescriptions(prescriptions);
//        }
//
//        return mapToResponse(savedRecord);
//    }
//
//    /**
//     * NEW: Handles Physical Report Uploads to Cloudinary (PDFs/Images).
//     * This record has a NULL doctor as it is patient-managed.
//     */
//    @Transactional
//    public MedicalRecordResponse uploadReport(UUID patientId, String title, MultipartFile file) throws IOException {
//        User patient = userRepository.findById(patientId)
//                .orElseThrow(() -> new RuntimeException("Patient not found"));
//
//        // 1. Store file in Cloudinary via our storage service
//        String secureUrl = fileStorageService.uploadFile(file);
//
//        // 2. Persist the link in the MedicalRecord table
//        MedicalRecord record = MedicalRecord.builder()
//                .patient(patient)
//                .doctor(null) // No doctor associated with self-upload
//                .title(title)
//                .fileUrl(secureUrl)
//                .fileType(file.getContentType())
//                .diagnosis("Personal Document Upload")
//                .build();
//
//        return mapToResponse(recordRepository.save(record));
//    }
//
//    /**
//     * Maps the Entity to a safe DTO for the Frontend.
//     */
//    private MedicalRecordResponse mapToResponse(MedicalRecord record) {
//        // Handle names safely to avoid NullPointerException on self-uploads
//        String docName = (record.getDoctor() != null && record.getDoctor().getUser() != null)
//                ? record.getDoctor().getUser().getFirstName() + " " + record.getDoctor().getUser().getLastName()
//                : "Self-Uploaded/External";
//
//        return MedicalRecordResponse.builder()
//                .id(record.getId())
//                .title(record.getTitle() != null ? record.getTitle() : "Medical Record")
//                .doctorName(docName)
//                .diagnosis(record.getDiagnosis())
//                .symptoms(record.getSymptoms())
//                .fileUrl(record.getFileUrl()) // Direct Cloudinary Link
//                .fileType(record.getFileType())
//                .date(record.getCreatedAt())
//                .prescriptions(record.getPrescriptions() != null ?
//                        record.getPrescriptions().stream()
//                                .map(p -> PrescriptionDTO.builder()
//                                        .medicineName(p.getMedicineName())
//                                        .dosage(p.getDosage())
//                                        .frequency(p.getFrequency())
//                                        .instructions(p.getInstructions())
//                                        .build())
//                                .collect(Collectors.toList()) : List.of())
//                .build();
//    }
//}


package com.medibot.healthcare_platform.modules.records.service;

// 1. IMPORT THE CORRECT RECORDS REPOSITORY
import com.medibot.healthcare_platform.modules.records.repository.MedicalRecordPrescriptionRepository;
import com.medibot.healthcare_platform.modules.records.repository.MedicalRecordRepository;
import com.medibot.healthcare_platform.modules.doctor.entity.Doctor;
import com.medibot.healthcare_platform.modules.doctor.repository.DoctorRepository;
import com.medibot.healthcare_platform.modules.identity.entity.User;
import com.medibot.healthcare_platform.modules.identity.repository.UserRepository;
import com.medibot.healthcare_platform.modules.records.entity.*;
import com.medibot.healthcare_platform.modules.records.dto.*;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class RecordService {

    private final MedicalRecordRepository recordRepository;
    // 2. USE THE UNIQUE RECORDS REPOSITORY TYPE
    private final MedicalRecordPrescriptionRepository prescriptionRepository;
    private final UserRepository userRepository;
    private final DoctorRepository doctorRepository;
    private final FileStorageService fileStorageService;

    /**
     * Retrieves all records (consultations and uploaded reports) for a patient.
     */
    public List<MedicalRecordResponse> getPatientHistory(UUID patientId) {
        return recordRepository.findByPatientIdOrderByCreatedAtDesc(patientId).stream()
                .map(this::mapToResponse)
                .collect(Collectors.toList());
    }

    /**
     * Handles creation of records by doctors (Prescriptions/Diagnosis).
     */
    @Transactional
    public MedicalRecordResponse createRecord(UUID patientId, UUID doctorId, MedicalRecordRequest request) {
        User patient = userRepository.findById(patientId)
                .orElseThrow(() -> new RuntimeException("Patient not found"));
        Doctor doctor = doctorRepository.findById(doctorId)
                .orElseThrow(() -> new RuntimeException("Doctor not found"));

        MedicalRecord record = MedicalRecord.builder()
                .patient(patient)
                .doctor(doctor)
                .title("Consultation Record")
                .diagnosis(request.getDiagnosis())
                .symptoms(request.getSymptoms())
                .build();

        MedicalRecord savedRecord = recordRepository.save(record);

        if (request.getPrescriptions() != null && !request.getPrescriptions().isEmpty()) {
            // 3. MAP TO records.entity.Prescription
            List<Prescription> prescriptions = request.getPrescriptions().stream()
                    .map(p -> Prescription.builder()
                            .medicalRecord(savedRecord)
                            .medicineName(p.getMedicineName())
                            .dosage(p.getDosage())
                            .frequency(p.getFrequency())
                            .instructions(p.getInstructions())
                            .build())
                    .collect(Collectors.toList());

            // 4. CALL THE CORRECT REPOSITORY
            prescriptionRepository.saveAll(prescriptions);
            savedRecord.setPrescriptions(prescriptions);
        }

        return mapToResponse(savedRecord);
    }

    /**
     * NEW: Handles Physical Report Uploads to Cloudinary (PDFs/Images).
     */
    @Transactional
    public MedicalRecordResponse uploadReport(UUID patientId, String title, MultipartFile file) throws IOException {
        User patient = userRepository.findById(patientId)
                .orElseThrow(() -> new RuntimeException("Patient not found"));

        String secureUrl = fileStorageService.uploadFile(file);

        MedicalRecord record = MedicalRecord.builder()
                .patient(patient)
                .doctor(null)
                .title(title)
                .fileUrl(secureUrl)
                .fileType(file.getContentType())
                .diagnosis("Personal Document Upload")
                .build();

        return mapToResponse(recordRepository.save(record));
    }

    /**
     * Maps the Entity to a safe DTO for the Frontend.
     */
    private MedicalRecordResponse mapToResponse(MedicalRecord record) {
        String docName = (record.getDoctor() != null && record.getDoctor().getUser() != null)
                ? record.getDoctor().getUser().getFirstName() + " " + record.getDoctor().getUser().getLastName()
                : "Self-Uploaded/External";

        return MedicalRecordResponse.builder()
                .id(record.getId())
                .title(record.getTitle() != null ? record.getTitle() : "Medical Record")
                .doctorName(docName)
                .diagnosis(record.getDiagnosis())
                .symptoms(record.getSymptoms())
                .fileUrl(record.getFileUrl())
                .fileType(record.getFileType())
                .date(record.getCreatedAt())
                .prescriptions(record.getPrescriptions() != null ?
                        record.getPrescriptions().stream()
                                .map(p -> PrescriptionDTO.builder()
                                        .medicineName(p.getMedicineName())
                                        .dosage(p.getDosage())
                                        .frequency(p.getFrequency())
                                        .instructions(p.getInstructions())
                                        .build())
                                .collect(Collectors.toList()) : List.of())
                .build();
    }
}