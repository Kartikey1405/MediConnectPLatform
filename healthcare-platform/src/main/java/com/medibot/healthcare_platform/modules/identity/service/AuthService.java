////////package com.medibot.healthcare_platform.modules.identity.service;
////////
////////import com.medibot.healthcare_platform.common.util.JwtUtils;
////////import com.medibot.healthcare_platform.modules.identity.dto.LoginRequest; // You need this DTO
////////import com.medibot.healthcare_platform.modules.identity.dto.AuthResponse;  // You need this DTO
////////import com.medibot.healthcare_platform.modules.identity.entity.User;
////////import com.medibot.healthcare_platform.modules.identity.repository.UserRepository;
////////import lombok.RequiredArgsConstructor;
////////import org.springframework.security.crypto.password.PasswordEncoder;
////////import org.springframework.stereotype.Service;
////////
////////@Service
////////@RequiredArgsConstructor
////////public class AuthService {
////////
////////    private final UserRepository userRepository;
////////    private final JwtUtils jwtUtils;
////////    private final PasswordEncoder passwordEncoder;
////////
////////    public AuthResponse login(LoginRequest request) {
////////        User user = userRepository.findByEmail(request.getEmail())
////////                .orElseThrow(() -> new RuntimeException("User not found with email: " + request.getEmail()));
////////
////////        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
////////            throw new RuntimeException("Invalid password. Please try again.");
////////        }
////////
////////        // Pass the role as a string to the JWT generator
////////        String token = jwtUtils.generateToken(user.getEmail(), user.getRole().name());
////////
////////        return AuthResponse.builder()
////////                .accessToken(token)
////////                .email(user.getEmail())
////////                .role(user.getRole().name())
////////                .build();
////////    }
////////}
//////
//////
//////package com.medibot.healthcare_platform.modules.identity.service;
//////
//////import com.medibot.healthcare_platform.common.util.JwtUtils;
//////import com.medibot.healthcare_platform.modules.identity.dto.LoginRequest;
//////import com.medibot.healthcare_platform.modules.identity.dto.AuthResponse;
//////import com.medibot.healthcare_platform.modules.identity.entity.User;
//////import com.medibot.healthcare_platform.modules.identity.repository.UserRepository;
//////import lombok.RequiredArgsConstructor;
//////import org.springframework.security.crypto.password.PasswordEncoder;
//////import org.springframework.stereotype.Service;
//////
//////@Service
//////@RequiredArgsConstructor
//////public class AuthService {
//////
//////    private final UserRepository userRepository;
//////    private final JwtUtils jwtUtils;
//////    private final PasswordEncoder passwordEncoder;
//////
//////    public AuthResponse login(LoginRequest request) {
//////        User user = userRepository.findByEmail(request.getEmail())
//////                .orElseThrow(() -> new RuntimeException("User not found"));
//////
//////        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
//////            throw new RuntimeException("Invalid credentials");
//////        }
//////
//////        // Pass the role to the token generator so the JWT carries authorization
//////        String token = jwtUtils.generateToken(user.getEmail(), user.getRole().name());
//////
//////        return AuthResponse.builder()
//////                .accessToken(token)
//////                .email(user.getEmail())
//////                .role(user.getRole().name())
//////                .build();
//////    }
//////}
////
////
////
////
////package com.medibot.healthcare_platform.modules.identity.service;
////
////import com.medibot.healthcare_platform.common.util.JwtUtils;
////import com.medibot.healthcare_platform.modules.identity.dto.LoginRequest;
////import com.medibot.healthcare_platform.modules.identity.dto.AuthResponse;
////import com.medibot.healthcare_platform.modules.identity.entity.User;
////import com.medibot.healthcare_platform.modules.identity.repository.UserRepository;
////import lombok.RequiredArgsConstructor;
////import org.springframework.security.crypto.password.PasswordEncoder;
////import org.springframework.stereotype.Service;
////
////@Service
////@RequiredArgsConstructor
////public class AuthService {
////
////    private final UserRepository userRepository;
////    private final JwtUtils jwtUtils;
////    private final PasswordEncoder passwordEncoder;
////
////    public AuthResponse login(LoginRequest request) {
////        User user = userRepository.findByEmail(request.getEmail())
////                .orElseThrow(() -> new RuntimeException("User not found"));
////
////        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
////            throw new RuntimeException("Invalid credentials");
////        }
////
////        // Pass the role to the token generator so the JWT carries authorization
////        String token = jwtUtils.generateToken(user.getEmail(), user.getRole().name());
////
////        // UPDATED: Now including the userId in the builder to synchronize with frontend
////        return AuthResponse.builder()
////                .accessToken(token)
////                .email(user.getEmail())
////                .role(user.getRole().name())
////                .userId(user.getId()) // This provides the UUID the frontend is looking for
////                .build();
////    }
////}
//
//
//
//package com.medibot.healthcare_platform.modules.identity.service;
//
//import com.medibot.healthcare_platform.common.util.JwtUtils;
//import com.medibot.healthcare_platform.modules.identity.dto.LoginRequest;
//import com.medibot.healthcare_platform.modules.identity.dto.AuthResponse;
//import com.medibot.healthcare_platform.modules.identity.entity.User;
//import com.medibot.healthcare_platform.modules.identity.repository.UserRepository;
//import com.medibot.healthcare_platform.modules.doctor.repository.DoctorRepository; // NEW: Needed for Doctor ID lookup
//import lombok.RequiredArgsConstructor;
//import org.springframework.security.crypto.password.PasswordEncoder;
//import org.springframework.stereotype.Service;
//
//import java.util.UUID;
//
//@Service
//@RequiredArgsConstructor
//public class AuthService {
//
//    private final UserRepository userRepository;
//    private final DoctorRepository doctorRepository; // NEW: Link between User and Specialist identity
//    private final JwtUtils jwtUtils;
//    private final PasswordEncoder passwordEncoder;
//
//    /**
//     * Authenticates a user and returns a full identity payload.
//     * Includes doctorId for clinical roles to fix empty dashboard issues.
//     */
//    public AuthResponse login(LoginRequest request) {
//        User user = userRepository.findByEmail(request.getEmail())
//                .orElseThrow(() -> new RuntimeException("User not found"));
//
//        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
//            throw new RuntimeException("Invalid credentials");
//        }
//
//        // Generate JWT with role-based claims
//        String token = jwtUtils.generateToken(user.getEmail(), user.getRole().name());
//
//        // 1. Build the base response with standard User info
//        AuthResponse.AuthResponseBuilder responseBuilder = AuthResponse.builder()
//                .accessToken(token)
//                .email(user.getEmail())
//                .role(user.getRole().name())
//                .firstName(user.getFirstName()) // For personalized greetings
//                .userId(user.getId());
//
//        // 2. CRITICAL: If role is DOCTOR, find the associated Specialist ID
//        // This solves the issue of the clinical queue being empty on the frontend.
//        if ("DOCTOR".equalsIgnoreCase(user.getRole().name())) {
//            doctorRepository.findByUserId(user.getId())
//                    .ifPresent(doctor -> responseBuilder.doctorId(doctor.getId()));
//        }
//
//        return responseBuilder.build();
//    }
//}

package com.medibot.healthcare_platform.modules.identity.service;

import com.medibot.healthcare_platform.common.util.JwtUtils;
import com.medibot.healthcare_platform.modules.identity.dto.LoginRequest;
import com.medibot.healthcare_platform.modules.identity.dto.AuthResponse;
import com.medibot.healthcare_platform.modules.identity.entity.User;
import com.medibot.healthcare_platform.modules.identity.repository.UserRepository;
import com.medibot.healthcare_platform.modules.doctor.repository.DoctorRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final DoctorRepository doctorRepository;
    private final JwtUtils jwtUtils;
    private final PasswordEncoder passwordEncoder;

    public AuthResponse login(LoginRequest request) {
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new RuntimeException("Login failed: User not found"));

        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new RuntimeException("Login failed: Invalid credentials");
        }

        String token = jwtUtils.generateToken(user.getEmail(), user.getRole().name());

        // Initialize response with User account data
        AuthResponse.AuthResponseBuilder responseBuilder = AuthResponse.builder()
                .accessToken(token)
                .email(user.getEmail())
                .role(user.getRole().name())
                .firstName(user.getFirstName())
                .userId(user.getId());

        // Map Specialist Identity if user is a DOCTOR
        if ("DOCTOR".equalsIgnoreCase(user.getRole().name())) {
            doctorRepository.findByUserId(user.getId())
                    .ifPresent(doctor -> responseBuilder.doctorId(doctor.getId()));
        }

        return responseBuilder.build();
    }
}