//package com.medibot.healthcare_platform.modules.identity.dto;
//
//import com.medibot.healthcare_platform.modules.identity.entity.Role;
//import jakarta.validation.constraints.Email;
//import jakarta.validation.constraints.NotBlank;
//import jakarta.validation.constraints.NotNull;
//import lombok.Data;
//
//@Data
//public class UserRequest {
//    @Email(message = "Invalid email format")
//    @NotBlank(message = "Email is required")
//    private String email;
//
//    @NotBlank(message = "Password is required")
//    private String password;
//
//    private String firstName;
//    private String lastName;
//
//    @NotNull(message = "Role is required")
//    private Role role;
//}


package com.medibot.healthcare_platform.modules.identity.dto;

import com.medibot.healthcare_platform.modules.identity.entity.Role;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
public class UserRequest {
    @Email(message = "Invalid email format")
    @NotBlank(message = "Email is required")
    private String email;

    @NotBlank(message = "Password is required")
    private String password;

    @NotBlank(message = "First name is required")
    private String firstName;

    private String lastName;

    // New mandatory clinical fields
    @NotNull(message = "Age is required")
    private Integer age;

    @NotBlank(message = "Gender is required")
    private String gender;

    private String medicalHistory; // Optional at signup, can be filled later

    @NotNull(message = "Role is required")
    private Role role;
}