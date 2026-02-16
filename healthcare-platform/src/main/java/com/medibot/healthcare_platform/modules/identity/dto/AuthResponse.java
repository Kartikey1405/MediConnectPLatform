//// modules/identity/dto/AuthResponse.java
//package com.medibot.healthcare_platform.modules.identity.dto;
//
//import com.fasterxml.jackson.annotation.JsonProperty;
//import lombok.*;
//import java.util.UUID;
//
//@Data
//@Builder
//@AllArgsConstructor
//@NoArgsConstructor
//public class AuthResponse {
//    private String accessToken;
//    private String email;
//    private String role;
//
//    @JsonProperty("userId") // FORCES the name in the JSON
//    private UUID userId;
//}



package com.medibot.healthcare_platform.modules.identity.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.*;
import java.util.UUID;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AuthResponse {
    private String accessToken;
    private String email;
    private String role;
    private String firstName; // Added for the "Welcome back, Dr. X" greeting

    @JsonProperty("userId")
    private UUID userId;

    // CRITICAL: The Doctor Entity ID needed for the Clinical Dashboard
    private UUID doctorId;
}