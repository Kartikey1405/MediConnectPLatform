//package com.medibot.healthcare_platform.modules.consultation.dto;
//
//import lombok.Data;
//import java.util.List;
//
//@Data
//public class PrescriptionRequest {
//    private String medicineName;
//    private String dosage;
//    private String frequency;
//    private String duration;
//    private String instructions;
//}

package com.medibot.healthcare_platform.modules.consultation.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PrescriptionRequest {
    private String medicineName;
    private String dosage;
    private String frequency;
    private String duration;
    private String instructions;
}