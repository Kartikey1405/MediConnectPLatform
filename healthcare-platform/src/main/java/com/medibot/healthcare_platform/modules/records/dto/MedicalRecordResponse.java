////package com.medibot.healthcare_platform.modules.records.dto;
////
////import lombok.Builder;
////import lombok.Data;
////import java.time.LocalDateTime;
////import java.util.List;
////import java.util.UUID;
////
////@Data
////@Builder
////public class MedicalRecordResponse {
////    private UUID id;
////    private String doctorName;
////    private String diagnosis;
////    private String symptoms;
////    private List<PrescriptionDTO> prescriptions;
////    private LocalDateTime date;
////}
//
//
//
//package com.medibot.healthcare_platform.modules.records.dto;
//
//import lombok.Builder;
//import lombok.Data;
//import java.time.LocalDateTime;
//import java.util.List;
//import java.util.UUID;
//
//@Data
//@Builder
//public class MedicalRecordResponse {
//    private UUID id;
//    private String title;
//    private String doctorName; // Will be "Self-Uploaded" if doctor is null
//    private String diagnosis;
//    private String symptoms;
//    private String fileUrl;    // For Cloudinary download/view
//    private String fileType;
//    private List<PrescriptionDTO> prescriptions;
//    private LocalDateTime date;
//}

package com.medibot.healthcare_platform.modules.records.dto;

import lombok.Builder;
import lombok.Data;
import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

@Data
@Builder
public class MedicalRecordResponse {
    private UUID id;
    private String title;
    private String doctorName; // Will be "Self-Uploaded" if doctor is null
    private String diagnosis;
    private String symptoms;
    private String fileUrl;    // For Cloudinary download/view
    private String fileType;
    private List<PrescriptionDTO> prescriptions;
    private LocalDateTime date;
}