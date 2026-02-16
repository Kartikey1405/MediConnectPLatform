////package com.medibot.healthcare_platform.modules.triage.dto;
////
////import lombok.Builder;
////import lombok.Data;
////import java.util.List;
////
////@Data
////@Builder
////public class TriageResponse {
////    private String predictedDisease;
////    private double confidence;
////    private String recommendedDepartment;
////
////    // Aligned with your Service Builder logic
////    private List<String> preventionTips;
////    private String redFlagWarning;
////}
//
//package com.medibot.healthcare_platform.modules.triage.dto;
//
//import lombok.Builder;
//import lombok.Data;
//import java.util.List;
//import java.util.Map;
//
//@Data
//@Builder
//public class TriageResponse {
//    private String predictedDisease;
//    private double confidence;
//    private String recommendedDepartment;
//    private List<String> preventionTips;
//    private String redFlagWarning;
//
//    // NEW: List to hold the 2nd and 3rd predictions for the UI bars
//    private List<Map<String, Object>> otherSuggestions;
//}



package com.medibot.healthcare_platform.modules.triage.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.util.List;
import java.util.Map;
import java.util.UUID; // Essential for the ID lookup

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class TriageResponse {
    private String predictedDisease;
    private double confidence;
    private String recommendedDepartment;

    // NEW: Enables the "Book Appointment" button to filter doctors automatically
    private UUID recommendedDepartmentId;

    private List<String> preventionTips;
    private String redFlagWarning;

    // NEW: Supports the 2nd and 3rd disease prediction bars in the UI
    private List<Map<String, Object>> otherSuggestions;
}