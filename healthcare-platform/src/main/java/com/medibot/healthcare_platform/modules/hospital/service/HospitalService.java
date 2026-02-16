////package com.medibot.healthcare_platform.modules.hospital.service;
////
////import com.medibot.healthcare_platform.modules.hospital.dto.*;
////import com.medibot.healthcare_platform.modules.hospital.entity.Hospital;
////import com.medibot.healthcare_platform.modules.hospital.entity.Department;
////import com.medibot.healthcare_platform.modules.hospital.repository.HospitalRepository;
////import com.medibot.healthcare_platform.modules.hospital.repository.DepartmentRepository;
////import lombok.RequiredArgsConstructor;
////import org.springframework.stereotype.Service;
////import org.springframework.transaction.annotation.Transactional;
////
////import java.util.List;
////import java.util.UUID;
////import java.util.stream.Collectors;
////
////@Service
////@RequiredArgsConstructor
////public class HospitalService {
////
////    private final HospitalRepository hospitalRepository;
////    private final DepartmentRepository departmentRepository;
////
////    // --- Hospital Logic ---
////
////    @Transactional
////    public HospitalResponse createHospital(HospitalRequest request) {
////        Hospital hospital = Hospital.builder()
////                .name(request.getName())
////                .address(request.getAddress())
////                .latitude(request.getLatitude())
////                .longitude(request.getLongitude())
////                .contactNumber(request.getContactNumber())
////                .isActive(true)
////                .build();
////
////        return mapToHospitalResponse(hospitalRepository.save(hospital));
////    }
////
////    public List<HospitalResponse> getAllHospitals() {
////        return hospitalRepository.findAll().stream()
////                .map(this::mapToHospitalResponse)
////                .collect(Collectors.toList());
////    }
////
////    public HospitalResponse getHospitalById(UUID id) {
////        Hospital hospital = hospitalRepository.findById(id)
////                .orElseThrow(() -> new RuntimeException("Hospital not found with id: " + id));
////        return mapToHospitalResponse(hospital);
////    }
////
////    @Transactional
////    public HospitalResponse updateHospital(UUID id, HospitalRequest request) {
////        Hospital hospital = hospitalRepository.findById(id)
////                .orElseThrow(() -> new RuntimeException("Hospital not found"));
////
////        hospital.setName(request.getName());
////        hospital.setAddress(request.getAddress());
////        hospital.setLatitude(request.getLatitude());
////        hospital.setLongitude(request.getLongitude());
////        hospital.setContactNumber(request.getContactNumber());
////
////        return mapToHospitalResponse(hospitalRepository.save(hospital));
////    }
////
////    @Transactional
////    public void deleteHospital(UUID id) {
////        hospitalRepository.deleteById(id);
////    }
////
////    // --- Department Logic ---
////
////    @Transactional
////    public DepartmentResponse addDepartmentToHospital(DepartmentRequest request) {
////        Hospital hospital = hospitalRepository.findById(request.getHospitalId())
////                .orElseThrow(() -> new RuntimeException("Hospital not found"));
////
////        Department department = Department.builder()
////                .name(request.getName())
////                .hospital(hospital)
////                .build();
////
////        return mapToDepartmentResponse(departmentRepository.save(department));
////    }
////
////    public List<DepartmentResponse> getDepartmentsByHospital(UUID hospitalId) {
////        return departmentRepository.findByHospitalId(hospitalId).stream()
////                .map(this::mapToDepartmentResponse)
////                .collect(Collectors.toList());
////    }
////
////    @Transactional
////    public void deleteDepartment(UUID id) {
////        departmentRepository.deleteById(id);
////    }
////
////    // --- Private Mapping Helpers (The Security Buffer) ---
////
////    private HospitalResponse mapToHospitalResponse(Hospital hospital) {
////        return HospitalResponse.builder()
////                .id(hospital.getId())
////                .name(hospital.getName())
////                .address(hospital.getAddress())
////                .contactNumber(hospital.getContactNumber())
////                .latitude(hospital.getLatitude())
////                .longitude(hospital.getLongitude())
////                .departments(hospital.getDepartments() != null ?
////                        hospital.getDepartments().stream()
////                                .map(this::mapToDepartmentResponse)
////                                .collect(Collectors.toList()) : null)
////                .build();
////    }
////
////    private DepartmentResponse mapToDepartmentResponse(Department department) {
////        return DepartmentResponse.builder()
////                .id(department.getId())
////                .name(department.getName())
////                .build();
////    }
////}
//
//
//
//package com.medibot.healthcare_platform.modules.hospital.service;
//
//import com.medibot.healthcare_platform.modules.hospital.dto.*;
//import com.medibot.healthcare_platform.modules.hospital.entity.Hospital;
//import com.medibot.healthcare_platform.modules.hospital.entity.Department;
//import com.medibot.healthcare_platform.modules.hospital.repository.HospitalRepository;
//import com.medibot.healthcare_platform.modules.hospital.repository.DepartmentRepository;
//import lombok.RequiredArgsConstructor;
//import lombok.extern.slf4j.Slf4j;
//import org.springframework.stereotype.Service;
//import org.springframework.transaction.annotation.Transactional;
//
//import java.util.List;
//import java.util.UUID;
//import java.util.stream.Collectors;
//
//@Service
//@RequiredArgsConstructor
//@Slf4j // Added for better clinical auditing/logging
//public class HospitalService {
//
//    private final HospitalRepository hospitalRepository;
//    private final DepartmentRepository departmentRepository;
//
//    // --- SOS & Public Discovery Logic ---
//
//    public List<HospitalResponse> getSOSNearHospitals(double lat, double lng) {
//        log.info("SOS Triggered. Finding nearest hospitals for coordinates: {}, {}", lat, lng);
//        // Uses the Haversine query from your repository (Radius: 20km)
//        return hospitalRepository.findNearestHospitals(lat, lng, 20.0)
//                .stream()
//                .map(this::mapToHospitalResponse)
//                .collect(Collectors.toList());
//    }
//
//    // --- Hospital CRUD Operations ---
//
//    @Transactional
//    public HospitalResponse createHospital(HospitalRequest request) {
//        Hospital hospital = Hospital.builder()
//                .name(request.getName())
//                .address(request.getAddress())
//                .latitude(request.getLatitude())
//                .longitude(request.getLongitude())
//                .contactNumber(request.getContactNumber())
//                .isActive(true)
//                .build();
//
//        log.info("Creating new hospital: {}", request.getName());
//        return mapToHospitalResponse(hospitalRepository.save(hospital));
//    }
//
//    public List<HospitalResponse> getAllHospitals() {
//        return hospitalRepository.findAll().stream()
//                .map(this::mapToHospitalResponse)
//                .collect(Collectors.toList());
//    }
//
//    public HospitalResponse getHospitalById(UUID id) {
//        return hospitalRepository.findById(id)
//                .map(this::mapToHospitalResponse)
//                .orElseThrow(() -> new RuntimeException("Hospital not found with id: " + id));
//    }
//
//    @Transactional
//    public HospitalResponse updateHospital(UUID id, HospitalRequest request) {
//        Hospital hospital = hospitalRepository.findById(id)
//                .orElseThrow(() -> new RuntimeException("Hospital not found"));
//
//        hospital.setName(request.getName());
//        hospital.setAddress(request.getAddress());
//        hospital.setLatitude(request.getLatitude());
//        hospital.setLongitude(request.getLongitude());
//        hospital.setContactNumber(request.getContactNumber());
//
//        log.info("Updated hospital record: {}", id);
//        return mapToHospitalResponse(hospitalRepository.save(hospital));
//    }
//
//    @Transactional
//    public void deleteHospital(UUID id) {
//        log.warn("Deleting hospital record: {}", id);
//        hospitalRepository.deleteById(id);
//    }
//
//    // --- Department CRUD Logic ---
//
//    @Transactional
//    public DepartmentResponse addDepartmentToHospital(DepartmentRequest request) {
//        Hospital hospital = hospitalRepository.findById(request.getHospitalId())
//                .orElseThrow(() -> new RuntimeException("Hospital reference missing for department creation."));
//
//        Department department = Department.builder()
//                .name(request.getName())
//                .specialty(request.getSpecialty()) // Maps to the DTO you provided
//                .consultationFee(request.getConsultationFee())
//                .hospital(hospital)
//                .build();
//
//        return mapToDepartmentResponse(departmentRepository.save(department));
//    }
//
//    public List<DepartmentResponse> getDepartmentsByHospital(UUID hospitalId) {
//        return departmentRepository.findByHospitalId(hospitalId).stream()
//                .map(this::mapToDepartmentResponse)
//                .collect(Collectors.toList());
//    }
//
//    public Hospital getRawHospitalById(UUID id) {
//        return hospitalRepository.findById(id)
//                .orElseThrow(() -> new RuntimeException("Hospital not found"));
//    }
//
//    public Department getRawDepartmentById(UUID id) {
//        return departmentRepository.findById(id)
//                .orElseThrow(() -> new RuntimeException("Department not found"));
//    }
//
//    @Transactional
//    public void deleteDepartment(UUID id) {
//        departmentRepository.deleteById(id);
//    }
//
//    // --- Mapping Logic (Internal/Private) ---
//
//    private HospitalResponse mapToHospitalResponse(Hospital hospital) {
//        return HospitalResponse.builder()
//                .id(hospital.getId())
//                .name(hospital.getName())
//                .address(hospital.getAddress())
//                .contactNumber(hospital.getContactNumber())
//                .latitude(hospital.getLatitude())
//                .longitude(hospital.getLongitude())
//                .departments(hospital.getDepartments() != null ?
//                        hospital.getDepartments().stream()
//                                .map(this::mapToDepartmentResponse)
//                                .collect(Collectors.toList()) : List.of())
//                .build();
//    }
//
//    private DepartmentResponse mapToDepartmentResponse(Department dept) {
//        return DepartmentResponse.builder()
//                .id(dept.getId())
//                .name(dept.getName())
//                .specialty(dept.getSpecialty())
//                .consultationFee(dept.getConsultationFee())
//                .build();
//    }
//}



package com.medibot.healthcare_platform.modules.hospital.service;

import com.medibot.healthcare_platform.modules.hospital.dto.*;
import com.medibot.healthcare_platform.modules.hospital.entity.Hospital;
import com.medibot.healthcare_platform.modules.hospital.entity.Department;
import com.medibot.healthcare_platform.modules.hospital.repository.HospitalRepository;
import com.medibot.healthcare_platform.modules.hospital.repository.DepartmentRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j // Enables clinical auditing and logging
public class HospitalService {

    private final HospitalRepository hospitalRepository;
    private final DepartmentRepository departmentRepository;

    // --- SOS & DISCOVERY LOGIC ---

    /**
     * Finds nearest hospitals within a 20km radius for emergency situations.
     */
    public List<HospitalResponse> getSOSNearHospitals(double lat, double lng) {
        log.info("SOS Triggered. Searching for facilities near: {}, {}", lat, lng);
        return hospitalRepository.findNearestHospitals(lat, lng, 20.0)
                .stream()
                .map(this::mapToHospitalResponse)
                .collect(Collectors.toList());
    }

    // --- HOSPITAL CRUD OPERATIONS ---

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

        log.info("Registering new hospital facility: {}", request.getName());
        return mapToHospitalResponse(hospitalRepository.save(hospital));
    }

    public List<HospitalResponse> getAllHospitals() {
        return hospitalRepository.findAll().stream()
                .map(this::mapToHospitalResponse)
                .collect(Collectors.toList());
    }

    public HospitalResponse getHospitalById(UUID id) {
        return hospitalRepository.findById(id)
                .map(this::mapToHospitalResponse)
                .orElseThrow(() -> new RuntimeException("Hospital record not found for ID: " + id));
    }

    @Transactional
    public HospitalResponse updateHospital(UUID id, HospitalRequest request) {
        Hospital hospital = hospitalRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Update failed: Hospital not found"));

        hospital.setName(request.getName());
        hospital.setAddress(request.getAddress());
        hospital.setLatitude(request.getLatitude());
        hospital.setLongitude(request.getLongitude());
        hospital.setContactNumber(request.getContactNumber());

        log.info("Successfully updated hospital record: {}", id);
        return mapToHospitalResponse(hospitalRepository.save(hospital));
    }

    @Transactional
    public void deleteHospital(UUID id) {
        log.warn("Permanently removing hospital record: {}", id);
        hospitalRepository.deleteById(id);
    }

    // --- DEPARTMENT MANAGEMENT LOGIC ---

    @Transactional
    public DepartmentResponse addDepartmentToHospital(DepartmentRequest request) {
        Hospital hospital = hospitalRepository.findById(request.getHospitalId())
                .orElseThrow(() -> new RuntimeException("Cannot add department: Hospital reference missing"));

        Department department = Department.builder()
                .name(request.getName())
                .specialty(request.getSpecialty()) // Links to the Specialty column for AI mapping
                .consultationFee(request.getConsultationFee())
                .hospital(hospital)
                .build();

        log.info("Added department '{}' to hospital '{}'", request.getName(), hospital.getName());
        return mapToDepartmentResponse(departmentRepository.save(department));
    }

    public List<DepartmentResponse> getDepartmentsByHospital(UUID hospitalId) {
        return departmentRepository.findByHospitalId(hospitalId).stream()
                .map(this::mapToDepartmentResponse)
                .collect(Collectors.toList());
    }

    @Transactional
    public void deleteDepartment(UUID id) {
        log.info("Removing department ID: {}", id);
        departmentRepository.deleteById(id);
    }

    // --- RAW ENTITY ACCESS (For Admin Cross-Module Logic) ---

    public Hospital getRawHospitalById(UUID id) {
        return hospitalRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Raw Hospital access failed: ID not found"));
    }

    public Department getRawDepartmentById(UUID id) {
        return departmentRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Raw Department access failed: ID not found"));
    }

    // --- PRIVATE MAPPING HELPERS ---

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
                                .collect(Collectors.toList()) : List.of())
                .build();
    }

    private DepartmentResponse mapToDepartmentResponse(Department dept) {
        return DepartmentResponse.builder()
                .id(dept.getId())
                .name(dept.getName())
                .specialty(dept.getSpecialty())
                .consultationFee(dept.getConsultationFee())
                .build();
    }
}