package com.medibot.healthcare_platform.modules.records.service;

import com.medibot.healthcare_platform.modules.doctor.entity.Doctor;
import com.medibot.healthcare_platform.modules.doctor.repository.DoctorRepository;
import com.medibot.healthcare_platform.modules.identity.entity.User;
import com.medibot.healthcare_platform.modules.identity.repository.UserRepository;
import com.medibot.healthcare_platform.modules.records.entity.*;
import com.medibot.healthcare_platform.modules.records.repository.*;
import com.medibot.healthcare_platform.modules.records.dto.*;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class RecordService {

    // These MUST be declared as final for @RequiredArgsConstructor to inject them
    private final MedicalRecordRepository recordRepository;
    private final PrescriptionRepository prescriptionRepository;
    private final UserRepository userRepository;
    private final DoctorRepository doctorRepository;

    public List<MedicalRecordResponse> getPatientHistory(UUID patientId) {
        return recordRepository.findByPatientIdOrderByCreatedAtDesc(patientId).stream()
                .map(this::mapToResponse)
                .collect(Collectors.toList());
    }

    @Transactional
    public MedicalRecordResponse createRecord(UUID patientId, UUID doctorId, MedicalRecordRequest request) {
        // Now these repositories will be recognized by the compiler
        User patient = userRepository.findById(patientId)
                .orElseThrow(() -> new RuntimeException("Patient not found"));
        Doctor doctor = doctorRepository.findById(doctorId)
                .orElseThrow(() -> new RuntimeException("Doctor not found"));

        MedicalRecord record = MedicalRecord.builder()
                .patient(patient)
                .doctor(doctor)
                .diagnosis(request.getDiagnosis())
                .symptoms(request.getSymptoms())
                .build();

        MedicalRecord savedRecord = recordRepository.save(record);

        if (request.getPrescriptions() != null && !request.getPrescriptions().isEmpty()) {
            List<Prescription> prescriptions = request.getPrescriptions().stream()
                    .map(p -> Prescription.builder()
                            .medicalRecord(savedRecord)
                            .medicineName(p.getMedicineName())
                            .dosage(p.getDosage())
                            .frequency(p.getFrequency())
                            .instructions(p.getInstructions())
                            .build())
                    .collect(Collectors.toList());

            prescriptionRepository.saveAll(prescriptions);
            savedRecord.setPrescriptions(prescriptions);
        }

        return mapToResponse(savedRecord);
    }

    private MedicalRecordResponse mapToResponse(MedicalRecord record) {
        return MedicalRecordResponse.builder()
                .id(record.getId())
                .doctorName(record.getDoctor().getUser().getFirstName() + " " + record.getDoctor().getUser().getLastName())
                .diagnosis(record.getDiagnosis())
                .symptoms(record.getSymptoms())
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