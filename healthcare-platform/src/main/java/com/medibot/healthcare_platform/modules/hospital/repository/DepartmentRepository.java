//////////////package com.medibot.healthcare_platform.modules.hospital.repository;
//////////////
//////////////import com.medibot.healthcare_platform.modules.hospital.entity.Department;
//////////////import org.springframework.data.jpa.repository.JpaRepository;
//////////////import java.util.List;
//////////////import java.util.UUID;
//////////////
//////////////public interface DepartmentRepository extends JpaRepository<Department, UUID> {
//////////////    // Used to populate the "Find Doctor" filters once a hospital is selected
//////////////    List<Department> findByHospitalId(UUID hospitalId);
//////////////}
////////////
////////////
////////////
////////////package com.medibot.healthcare_platform.modules.hospital.repository;
////////////
////////////import com.medibot.healthcare_platform.modules.hospital.entity.Department;
////////////import org.springframework.data.jpa.repository.JpaRepository;
////////////import java.util.List;
////////////import java.util.Optional; // Added import
////////////import java.util.UUID;
////////////
////////////public interface DepartmentRepository extends JpaRepository<Department, UUID> {
////////////
////////////    // Find all departments for a specific hospital
////////////    List<Department> findByHospitalId(UUID hospitalId);
////////////
////////////    /**
////////////     * CRITICAL: Links AI text recommendations to database IDs.
////////////     * Case-insensitive search helps prevent "Cardiology" vs "cardiology" mismatches.
////////////     */
////////////    Optional<Department> findByNameIgnoreCase(String name);
////////////}
//////////
//////////package com.medibot.healthcare_platform.modules.hospital.repository;
//////////
//////////import com.medibot.healthcare_platform.modules.hospital.entity.Department;
//////////import org.springframework.data.jpa.repository.JpaRepository;
//////////import java.util.List;
//////////import java.util.Optional; // Ensure this is imported
//////////import java.util.UUID;
//////////
//////////public interface DepartmentRepository extends JpaRepository<Department, UUID> {
//////////
//////////    List<Department> findByHospitalId(UUID hospitalId);
//////////
//////////    // FIX: Add this exact method name to satisfy the TriageService call
//////////    Optional<Department> findByName(String name);
//////////}
////////
////////package com.medibot.healthcare_platform.modules.hospital.repository;
////////
////////import com.medibot.healthcare_platform.modules.hospital.entity.Department;
////////import org.springframework.data.jpa.repository.JpaRepository;
////////import java.util.List;
////////import java.util.Optional;
////////import java.util.UUID;
////////
////////public interface DepartmentRepository extends JpaRepository<Department, UUID> {
////////
////////    List<Department> findByHospitalId(UUID hospitalId);
////////
////////    /**
////////     * FIX: Matches the AI's simple output against the "specialty" column.
////////     * Example: "Dermatology" matches "DERMATOLOGY" regardless of case.
////////     */
////////    Optional<Department> findBySpecialtyIgnoreCase(String specialty);
////////}
//////
//////
//////package com.medibot.healthcare_platform.modules.hospital.repository;
//////
//////import com.medibot.healthcare_platform.modules.hospital.entity.Department;
//////import org.springframework.data.jpa.repository.JpaRepository;
//////import java.util.List;
//////import java.util.Optional;
//////import java.util.UUID;
//////
//////public interface DepartmentRepository extends JpaRepository<Department, UUID> {
//////
//////    List<Department> findByHospitalId(UUID hospitalId);
//////
//////    /**
//////     * FIX: Matches AI text output (e.g., "Dermatology") against the clean "specialty" column.
//////     * This is more reliable than matching descriptive department names.
//////     */
//////    Optional<Department> findBySpecialtyIgnoreCase(String specialty);
//////}
////
////
////
////package com.medibot.healthcare_platform.modules.hospital.repository;
////
////import com.medibot.healthcare_platform.modules.hospital.entity.Department;
////import org.springframework.data.jpa.repository.JpaRepository;
////import org.springframework.data.jpa.repository.Query;
////import org.springframework.data.repository.query.Param;
////import java.util.List;
////import java.util.Optional;
////import java.util.UUID;
////
////public interface DepartmentRepository extends JpaRepository<Department, UUID> {
////
////    List<Department> findByHospitalId(UUID hospitalId);
////
////    Optional<Department> findBySpecialtyIgnoreCase(String specialty);
////
////    /**
////     * FUZZY SEARCH: Matches partial words against both name and specialty.
////     * Use this to bridge varied AI outputs (e.g., "Pulmonology") to
////     * specific DB entries (e.g., "Pulmonology & Chest Clinic").
////     */
////    @Query("SELECT d FROM Department d WHERE " +
////            "LOWER(d.name) LIKE LOWER(CONCAT('%', :keyword, '%')) OR " +
////            "LOWER(d.specialty) LIKE LOWER(CONCAT('%', :keyword, '%'))")
////    List<Department> searchByFuzzyKeyword(@Param("keyword") String keyword);
////}
//
//
//
//
////////
////////
////////
////////package com.medibot.healthcare_platform.modules.triage.service;
////////
////////import com.medibot.healthcare_platform.modules.hospital.entity.Department;
////////import com.medibot.healthcare_platform.modules.triage.client.FastApiClient;
////////import com.medibot.healthcare_platform.modules.triage.client.GeminiClient;
////////import com.medibot.healthcare_platform.modules.triage.dto.FastApiResponse;
////////import com.medibot.healthcare_platform.modules.triage.dto.TriageResponse;
////////import lombok.RequiredArgsConstructor;
////////import org.springframework.stereotype.Service;
////////import java.util.*;
////////import java.util.stream.Collectors;
////////
////////@Service
////////@RequiredArgsConstructor
////////public class TriageService {
////////    private final FastApiClient fastApiClient;
////////    private final GeminiClient geminiClient;
////////
////////    public TriageResponse analyzeSymptoms(List<String> symptoms) {
////////        FastApiResponse aiResult = fastApiClient.getPrediction(symptoms).block();
////////
////////        if (aiResult == null || aiResult.getPredictions() == null || aiResult.getPredictions().isEmpty()) {
////////            String feedback = (aiResult != null && aiResult.getError() != null) ? aiResult.getError() : "Need more info.";
////////            return TriageResponse.builder().predictedDisease("Needs More Detail").recommendedDepartment("General Physician").redFlagWarning(feedback).build();
////////        }
////////
////////        var topResult = aiResult.getPredictions().get(0);
////////        String disease = topResult.getDisease();
////////
////////        // FIX: Mapping the top 3 with type-safe HashMap to avoid 'collect' error
////////        List<Map<String, Object>> otherSuggestions = aiResult.getPredictions().stream()
////////                .skip(1)
////////                .map(p -> {
////////                    Map<String, Object> map = new HashMap<>();
////////                    map.put("name", p.getDisease());
////////                    map.put("confidence", (int)(p.getConfidence() * 100));
////////                    return map;
////////                }).collect(Collectors.toList());
////////
////////        // ROUTING LOGIC: Simple vs Specialist
////////        String aiAdvice;
////////        boolean isSimple = disease.contains("Migraine") || (symptoms.size() <= 2 && (disease.contains("Fever") || disease.contains("Cold")));
////////
////////        if (isSimple) {
////////            aiAdvice = "DEPT: General Physician | TIPS: Rest adequately, Stay hydrated, Monitor temperature | WARNING: Seek care if symptoms persist beyond 3 days.";
////////        } else {
////////            aiAdvice = geminiClient.getClinicalAdvice(disease);
////////        }
////////
////////        TriageResponse response = parseAndBuild(disease, topResult.getConfidence(), aiAdvice);
////////        response.setOtherSuggestions(otherSuggestions);
////////        return response;
////////    }
////////
////////    private TriageResponse parseAndBuild(String disease, double confidence, String aiAdvice) {
////////        String[] parts = aiAdvice.split("\\|");
////////        String dept = parts[0].replace("DEPT:", "").trim();
////////        List<String> tips = Arrays.stream(parts[1].replace("TIPS:", "").split(",")).map(String::trim).toList();
////////        String warning = parts[2].replace("WARNING:", "").trim();
////////
////////        return TriageResponse.builder()
////////                .predictedDisease(disease).confidence(confidence)
////////                .recommendedDepartment(dept).preventionTips(tips).redFlagWarning(warning)
////////                .build();
////////    }
////////    // Inside TriageService.java
////////    public TriageResponse analyzeSymptoms(List<String> symptoms) {
////////        // 1. Get ML prediction (e.g., Bronchial Asthma)
////////        // 2. Get Gemini advice (e.g., SERVICE: Pulmonology)
////////        String advice = geminiClient.getClinicalAdvice(prediction);
////////
////////        // 3. Extract the department name from the string
////////        String deptName = extractDeptName(advice);
////////
////////        // 4. Look up the Department ID in your database
////////        UUID deptId = departmentRepository.findByName(deptName)
////////                .map(Department::getId)
////////                .orElse(null);
////////
////////        return TriageResponse.builder()
////////                .predictedDisease(prediction)
////////                .recommendedDepartment(deptName)
////////                .recommendedDepartmentId(deptId) // ADD THIS to your TriageResponse DTO
////////                .preventionTips(tips)
////////                .build();
////////    }
////////}
//////
//////
//////
//////
//////
////////package com.medibot.healthcare_platform.modules.triage.service;
////////
////////import com.medibot.healthcare_platform.modules.hospital.entity.Department;
////////import com.medibot.healthcare_platform.modules.hospital.repository.DepartmentRepository;
////////import com.medibot.healthcare_platform.modules.triage.client.FastApiClient;
////////import com.medibot.healthcare_platform.modules.triage.client.GeminiClient;
////////import com.medibot.healthcare_platform.modules.triage.dto.FastApiResponse;
////////import com.medibot.healthcare_platform.modules.triage.dto.TriageResponse;
////////import lombok.RequiredArgsConstructor;
////////import lombok.extern.slf4j.Slf4j;
////////import org.springframework.stereotype.Service;
////////
////////import java.util.*;
////////import java.util.stream.Collectors;
////////
////////@Service
////////@RequiredArgsConstructor
////////@Slf4j
////////public class TriageService {
////////
////////    private final FastApiClient fastApiClient;
////////    private final GeminiClient geminiClient;
////////    private final DepartmentRepository departmentRepository; // Injected to link AI text to DB IDs
////////
////////    public TriageResponse analyzeSymptoms(List<String> symptoms) {
////////        // 1. Call FastAPI (Python) for Disease Prediction
////////        FastApiResponse aiResult = fastApiClient.getPrediction(symptoms).block();
////////
////////        // 2. Guardrail: Handle empty or failed predictions
////////        if (aiResult == null || aiResult.getPredictions() == null || aiResult.getPredictions().isEmpty()) {
////////            String feedback = (aiResult != null && aiResult.getError() != null) ? aiResult.getError() : "Need more info.";
////////            return TriageResponse.builder()
////////                    .predictedDisease("Needs More Detail")
////////                    .recommendedDepartment("General Physician")
////////                    .redFlagWarning(feedback)
////////                    .build();
////////        }
////////
////////        var topResult = aiResult.getPredictions().get(0);
////////        String disease = topResult.getDisease();
////////
////////        // 3. Map secondary predictions for UI bars
////////        List<Map<String, Object>> otherSuggestions = aiResult.getPredictions().stream()
////////                .skip(1)
////////                .map(p -> {
////////                    Map<String, Object> map = new HashMap<>();
////////                    map.put("name", p.getDisease());
////////                    map.put("confidence", (int)(p.getConfidence() * 100));
////////                    return map;
////////                }).collect(Collectors.toList());
////////
////////        // 4. Routing Logic: Simple vs Specialist advice
////////        String aiAdvice;
////////        boolean isSimple = disease.contains("Migraine") ||
////////                (symptoms.size() <= 2 && (disease.contains("Fever") || disease.contains("Cold")));
////////
////////        if (isSimple) {
////////            aiAdvice = "DEPT: General Physician | TIPS: Rest adequately, Stay hydrated, Monitor temperature | WARNING: Seek care if symptoms persist beyond 3 days.";
////////        } else {
////////            log.info("Requesting specialist clinical advice for: {}", disease);
////////            aiAdvice = geminiClient.getClinicalAdvice(disease);
////////        }
////////
////////        // 5. Build final response with DB ID lookup
////////        TriageResponse response = parseAndBuild(disease, topResult.getConfidence(), aiAdvice);
////////        response.setOtherSuggestions(otherSuggestions);
////////
////////        return response;
////////    }
////////
////////    private TriageResponse parseAndBuild(String disease, double confidence, String aiAdvice) {
////////        try {
////////            String[] parts = aiAdvice.split("\\|");
////////
////////            // Robust parsing: Handles "DEPT:" or "SERVICE:" prefixes from different prompt versions
////////            String deptName = parts[0].replaceAll("(?i)(DEPT:|SERVICE:)", "").trim();
////////
////////            List<String> tips = Arrays.stream(parts[1].replaceAll("(?i)(TIPS:|GUIDELINES:)", "").split(","))
////////                    .map(String::trim).toList();
////////
////////            String warning = parts[2].replaceAll("(?i)(WARNING:|ALERT:)", "").trim();
////////
////////            // DATABASE LOOKUP: Convert AI string to valid UUID
////////            UUID deptId = departmentRepository.findByName(deptName)
////////                    .map(Department::getId)
////////                    .orElse(null);
////////
////////            return TriageResponse.builder()
////////                    .predictedDisease(disease)
////////                    .confidence(confidence)
////////                    .recommendedDepartment(deptName)
////////                    .recommendedDepartmentId(deptId) // Crucial for the "Book Appointment" navigation
////////                    .preventionTips(tips)
////////                    .redFlagWarning(warning)
////////                    .build();
////////
////////        } catch (Exception e) {
////////            log.error("Failed to parse AI advice: {}. Error: {}", aiAdvice, e.getMessage());
////////            return TriageResponse.builder()
////////                    .predictedDisease(disease)
////////                    .confidence(confidence)
////////                    .recommendedDepartment("General Physician")
////////                    .preventionTips(List.of("Rest adequately", "Monitor symptoms"))
////////                    .redFlagWarning("Could not generate clinical tips. Please consult a professional.")
////////                    .build();
////////        }
////////    }
////////}
//////
//////
//////
//////package com.medibot.healthcare_platform.modules.triage.service;
//////
//////import com.medibot.healthcare_platform.modules.hospital.entity.Department;
//////import com.medibot.healthcare_platform.modules.hospital.repository.DepartmentRepository;
//////import com.medibot.healthcare_platform.modules.triage.client.FastApiClient;
//////import com.medibot.healthcare_platform.modules.triage.client.GeminiClient;
//////import com.medibot.healthcare_platform.modules.triage.dto.FastApiResponse;
//////import com.medibot.healthcare_platform.modules.triage.dto.TriageResponse;
//////import lombok.RequiredArgsConstructor;
//////import lombok.extern.slf4j.Slf4j;
//////import org.springframework.stereotype.Service;
//////
//////import java.util.*;
//////        import java.util.stream.Collectors;
//////
//////@Service
//////@RequiredArgsConstructor
//////@Slf4j
//////public class TriageService {
//////
//////    private final FastApiClient fastApiClient;
//////    private final GeminiClient geminiClient;
//////    private final DepartmentRepository departmentRepository; // Injected for DB mapping
//////
//////    public TriageResponse analyzeSymptoms(List<String> symptoms) {
//////        // 1. Call FastAPI for Prediction
//////        FastApiResponse aiResult = fastApiClient.getPrediction(symptoms).block();
//////
//////        // 2. Guardrail Cases
//////        if (aiResult == null || aiResult.getPredictions() == null || aiResult.getPredictions().isEmpty()) {
//////            String feedback = (aiResult != null && aiResult.getError() != null) ? aiResult.getError() : "Need more info.";
//////            return TriageResponse.builder()
//////                    .predictedDisease("Needs More Detail")
//////                    .recommendedDepartment("General Physician")
//////                    .redFlagWarning(feedback)
//////                    .build();
//////        }
//////
//////        var topResult = aiResult.getPredictions().get(0);
//////        String disease = topResult.getDisease();
//////
//////        // 3. Map secondary predictions for UI bars
//////        List<Map<String, Object>> otherSuggestions = aiResult.getPredictions().stream()
//////                .skip(1)
//////                .map(p -> {
//////                    Map<String, Object> map = new HashMap<>();
//////                    map.put("name", p.getDisease());
//////                    map.put("confidence", (int)(p.getConfidence() * 100));
//////                    return map;
//////                }).collect(Collectors.toList());
//////
//////        // 4. Routing Logic: Simple vs Specialist advice
//////        String aiAdvice;
//////        boolean isSimple = disease.contains("Migraine") ||
//////                (symptoms.size() <= 2 && (disease.contains("Fever") || disease.contains("Cold")));
//////
//////        if (isSimple) {
//////            aiAdvice = "DEPT: General Physician | TIPS: Rest adequately, Stay hydrated, Monitor temperature | WARNING: Seek care if symptoms persist beyond 3 days.";
//////        } else {
//////            log.info("Requesting specialist clinical advice for: {}", disease);
//////            aiAdvice = geminiClient.getClinicalAdvice(disease);
//////        }
//////
//////        // 5. Build and attach theSuggestions
//////        TriageResponse response = parseAndBuild(disease, topResult.getConfidence(), aiAdvice);
//////        response.setOtherSuggestions(otherSuggestions);
//////
//////        return response;
//////    }
//////
//////    private TriageResponse parseAndBuild(String disease, double confidence, String aiAdvice) {
//////        try {
//////            String[] parts = aiAdvice.split("\\|");
//////
//////            // Robust parsing: Handles "DEPT:" or "SERVICE:" prefixes
//////            String deptName = parts[0].replaceAll("(?i)(DEPT:|SERVICE:)", "").trim();
//////
//////            List<String> tips = Arrays.stream(parts[1].replaceAll("(?i)(TIPS:|GUIDELINES:)", "").split(","))
//////                    .map(String::trim).toList();
//////
//////            String warning = parts[2].replaceAll("(?i)(WARNING:|ALERT:)", "").trim();
//////
//////            // DATABASE LOOKUP: Linking text recommendation to physical DB ID
//////            UUID deptId = departmentRepository.findByName(deptName)
//////                    .map(Department::getId)
//////                    .orElse(null);
//////
//////            return TriageResponse.builder()
//////                    .predictedDisease(disease)
//////                    .confidence(confidence)
//////                    .recommendedDepartment(deptName)
//////                    .recommendedDepartmentId(deptId) // Set the UUID here
//////                    .preventionTips(tips)
//////                    .redFlagWarning(warning)
//////                    .build();
//////
//////        } catch (Exception e) {
//////            log.error("Failed to parse AI advice: {}. Error: {}", aiAdvice, e.getMessage());
//////            return TriageResponse.builder()
//////                    .predictedDisease(disease)
//////                    .confidence(confidence)
//////                    .recommendedDepartment("General Physician")
//////                    .preventionTips(List.of("Rest adequately", "Monitor symptoms"))
//////                    .redFlagWarning("Could not generate clinical tips. Please consult a professional.")
//////                    .build();
//////        }
//////    }
//////}
////
////
////package com.medibot.healthcare_platform.modules.triage.service;
////
////import com.medibot.healthcare_platform.modules.hospital.entity.Department;
////import com.medibot.healthcare_platform.modules.hospital.repository.DepartmentRepository;
////import com.medibot.healthcare_platform.modules.triage.client.FastApiClient;
////import com.medibot.healthcare_platform.modules.triage.client.GeminiClient;
////import com.medibot.healthcare_platform.modules.triage.dto.FastApiResponse;
////import com.medibot.healthcare_platform.modules.triage.dto.TriageResponse;
////import lombok.RequiredArgsConstructor;
////import lombok.extern.slf4j.Slf4j;
////import org.springframework.stereotype.Service;
////
////import java.util.*;
////import java.util.stream.Collectors;
////
////@Service
////@RequiredArgsConstructor
////@Slf4j
////public class TriageService {
////
////    private final FastApiClient fastApiClient;
////    private final GeminiClient geminiClient;
////    private final DepartmentRepository departmentRepository;
////
////    public TriageResponse analyzeSymptoms(List<String> symptoms) {
////        FastApiResponse aiResult = fastApiClient.getPrediction(symptoms).block();
////
////        if (aiResult == null || aiResult.getPredictions() == null || aiResult.getPredictions().isEmpty()) {
////            String feedback = (aiResult != null && aiResult.getError() != null) ? aiResult.getError() : "Need more info.";
////            return TriageResponse.builder()
////                    .predictedDisease("Needs More Detail")
////                    .recommendedDepartment("General Physician")
////                    .redFlagWarning(feedback)
////                    .build();
////        }
////
////        var topResult = aiResult.getPredictions().get(0);
////        String disease = topResult.getDisease();
////
////        List<Map<String, Object>> otherSuggestions = aiResult.getPredictions().stream()
////                .skip(1)
////                .map(p -> {
////                    Map<String, Object> map = new HashMap<>();
////                    map.put("name", p.getDisease());
////                    map.put("confidence", (int)(p.getConfidence() * 100));
////                    return map;
////                }).collect(Collectors.toList());
////
////        String aiAdvice;
////        boolean isSimple = disease.contains("Migraine") ||
////                (symptoms.size() <= 2 && (disease.contains("Fever") || disease.contains("Cold")));
////
////        if (isSimple) {
////            aiAdvice = "DEPT: General Physician | TIPS: Rest adequately, Stay hydrated, Monitor temperature | WARNING: Seek care if symptoms persist beyond 3 days.";
////        } else {
////            aiAdvice = geminiClient.getClinicalAdvice(disease);
////        }
////
////        TriageResponse response = parseAndBuild(disease, topResult.getConfidence(), aiAdvice);
////        response.setOtherSuggestions(otherSuggestions);
////
////        return response;
////    }
////
////    private TriageResponse parseAndBuild(String disease, double confidence, String aiAdvice) {
////        try {
////            String[] parts = aiAdvice.split("\\|");
////
////            String deptName = parts[0].replaceAll("(?i)(DEPT:|SERVICE:)", "").trim();
////
////            List<String> tips = Arrays.stream(parts[1].replaceAll("(?i)(TIPS:|GUIDELINES:)", "").split(","))
////                    .map(String::trim).toList();
////
////            String warning = parts[2].replaceAll("(?i)(WARNING:|ALERT:)", "").trim();
////
////            // FIX: Search by Specialty column to bridge AI output to DB records
////            UUID deptId = departmentRepository.findBySpecialtyIgnoreCase(deptName)
////                    .map(Department::getId)
////                    .orElse(null);
////
////            return TriageResponse.builder()
////                    .predictedDisease(disease)
////                    .confidence(confidence)
////                    .recommendedDepartment(deptName)
////                    .recommendedDepartmentId(deptId) // Button triggers when this is not null
////                    .preventionTips(tips)
////                    .redFlagWarning(warning)
////                    .build();
////
////        } catch (Exception e) {
////            log.error("Failed to parse AI advice: {}. Error: {}", aiAdvice, e.getMessage());
////            return TriageResponse.builder()
////                    .predictedDisease(disease)
////                    .confidence(confidence)
////                    .recommendedDepartment("General Physician")
////                    .preventionTips(List.of("Rest adequately", "Monitor symptoms"))
////                    .redFlagWarning("Could not generate clinical tips. Please consult a professional.")
////                    .build();
////        }
////    }
////}
//
//
//
//package com.medibot.healthcare_platform.modules.hospital.repository;
//
//import com.medibot.healthcare_platform.modules.hospital.entity.Department;
//import org.springframework.data.jpa.repository.JpaRepository;
//import org.springframework.data.jpa.repository.Query;
//import org.springframework.data.repository.query.Param;
//import java.util.List;
//import java.util.Optional;
//import java.util.UUID;
//
//public interface DepartmentRepository extends JpaRepository<Department, UUID> {
//
//    List<Department> findByHospitalId(UUID hospitalId);
//
//    Optional<Department> findBySpecialtyIgnoreCase(String specialty);
//
//    /**
//     * FUZZY SEARCH: Matches keywords against both name and specialty.
//     * Essential for routing AI text (e.g., "Infectious Disease") to
//     * specific database entries.
//     */
//    @Query("SELECT d FROM Department d WHERE " +
//            "LOWER(d.name) LIKE LOWER(CONCAT('%', :keyword, '%')) OR " +
//            "LOWER(d.specialty) LIKE LOWER(CONCAT('%', :keyword, '%'))")
//    List<Department> searchByFuzzyKeyword(@Param("keyword") String keyword);
//}



package com.medibot.healthcare_platform.modules.hospital.repository;

import com.medibot.healthcare_platform.modules.hospital.entity.Department;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface DepartmentRepository extends JpaRepository<Department, UUID> {

    // Used for "Find Doctor" filters
    List<Department> findByHospitalId(UUID hospitalId);

    // Primary lookup for TriageService
    Optional<Department> findBySpecialtyIgnoreCase(String specialty);

    // Fallback lookup if AI uses full names (e.g., "Emergency & Trauma")
    Optional<Department> findByNameIgnoreCase(String name);

    /**
     * FUZZY SEARCH: Bridges varied AI naming to your DB entries.
     * Matches keywords across Name and Specialty columns.
     */
    @Query("SELECT d FROM Department d WHERE " +
            "LOWER(d.name) LIKE LOWER(CONCAT('%', :keyword, '%')) OR " +
            "LOWER(d.specialty) LIKE LOWER(CONCAT('%', :keyword, '%'))")
    List<Department> searchByFuzzyKeyword(@Param("keyword") String keyword);
}