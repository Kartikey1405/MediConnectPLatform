////package com.medibot.healthcare_platform.modules.identity.dto;
////
////import com.medibot.healthcare_platform.modules.identity.entity.Role;
////import lombok.Builder;
////import lombok.Data;
////import java.util.UUID;
////
////@Data
////@Builder
////public class UserResponse {
////    private UUID id;
////    private String email;
////    private String firstName;
////    private String lastName;
////    private Role role;
////}
//
package com.medibot.healthcare_platform.modules.identity.dto;

import com.medibot.healthcare_platform.modules.identity.entity.Role;
import lombok.Builder;
import lombok.Data;
import java.util.UUID;

@Data
@Builder
public class UserResponse {
    private UUID id;
    private String email;
    private String firstName;
    private String lastName;
    private Integer age;
    private String gender;
    private String medicalHistory;
    private Role role;
}

