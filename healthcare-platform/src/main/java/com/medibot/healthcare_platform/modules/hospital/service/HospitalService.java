package com.medibot.healthcare_platform.modules.hospital.service;

import com.medibot.healthcare_platform.modules.hospital.dto.*;
import com.medibot.healthcare_platform.modules.hospital.entity.Hospital;
import com.medibot.healthcare_platform.modules.hospital.entity.Department;
import com.medibot.healthcare_platform.modules.hospital.repository.HospitalRepository;
import com.medibot.healthcare_platform.modules.hospital.repository.DepartmentRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class HospitalService {

    private final HospitalRepository hospitalRepository;
    private final DepartmentRepository departmentRepository;

    // --- Hospital Logic ---

    @Transactional
    public HospitalResponse createHospital(HospitalRequest request) {
        Hospital hospital = Hospital.builder()
                .name(request.getName())
                .address(request.getAddress())
                .latitude(request.getLatitude())
                .longitude(request.getLongitude())
                .contactNumber(request.getContactNumber())
                .isActive(true)
                .build();

        return mapToHospitalResponse(hospitalRepository.save(hospital));
    }

    public List<HospitalResponse> getAllHospitals() {
        return hospitalRepository.findAll().stream()
                .map(this::mapToHospitalResponse)
                .collect(Collectors.toList());
    }

    public HospitalResponse getHospitalById(UUID id) {
        Hospital hospital = hospitalRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Hospital not found with id: " + id));
        return mapToHospitalResponse(hospital);
    }

    @Transactional
    public HospitalResponse updateHospital(UUID id, HospitalRequest request) {
        Hospital hospital = hospitalRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Hospital not found"));

        hospital.setName(request.getName());
        hospital.setAddress(request.getAddress());
        hospital.setLatitude(request.getLatitude());
        hospital.setLongitude(request.getLongitude());
        hospital.setContactNumber(request.getContactNumber());

        return mapToHospitalResponse(hospitalRepository.save(hospital));
    }

    @Transactional
    public void deleteHospital(UUID id) {
        hospitalRepository.deleteById(id);
    }

    // --- Department Logic ---

    @Transactional
    public DepartmentResponse addDepartmentToHospital(DepartmentRequest request) {
        Hospital hospital = hospitalRepository.findById(request.getHospitalId())
                .orElseThrow(() -> new RuntimeException("Hospital not found"));

        Department department = Department.builder()
                .name(request.getName())
                .hospital(hospital)
                .build();

        return mapToDepartmentResponse(departmentRepository.save(department));
    }

    public List<DepartmentResponse> getDepartmentsByHospital(UUID hospitalId) {
        return departmentRepository.findByHospitalId(hospitalId).stream()
                .map(this::mapToDepartmentResponse)
                .collect(Collectors.toList());
    }

    @Transactional
    public void deleteDepartment(UUID id) {
        departmentRepository.deleteById(id);
    }

    // --- Private Mapping Helpers (The Security Buffer) ---

    private HospitalResponse mapToHospitalResponse(Hospital hospital) {
        return HospitalResponse.builder()
                .id(hospital.getId())
                .name(hospital.getName())
                .address(hospital.getAddress())
                .contactNumber(hospital.getContactNumber())
                .latitude(hospital.getLatitude())
                .longitude(hospital.getLongitude())
                .departments(hospital.getDepartments() != null ?
                        hospital.getDepartments().stream()
                                .map(this::mapToDepartmentResponse)
                                .collect(Collectors.toList()) : null)
                .build();
    }

    private DepartmentResponse mapToDepartmentResponse(Department department) {
        return DepartmentResponse.builder()
                .id(department.getId())
                .name(department.getName())
                .build();
    }
}