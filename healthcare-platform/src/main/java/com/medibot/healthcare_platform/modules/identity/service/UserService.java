//package com.medibot.healthcare_platform.modules.identity.service;
//
//import com.medibot.healthcare_platform.modules.identity.dto.*;
//import com.medibot.healthcare_platform.modules.identity.entity.User;
//import com.medibot.healthcare_platform.modules.identity.repository.UserRepository;
//import lombok.RequiredArgsConstructor;
//import org.springframework.security.crypto.password.PasswordEncoder;
//import org.springframework.stereotype.Service;
//import org.springframework.transaction.annotation.Transactional;
//
//import java.util.List;
//import java.util.UUID;
//import java.util.stream.Collectors;
//
//@Service
//@RequiredArgsConstructor
//public class UserService {
//    private final UserRepository userRepository;
//    private final PasswordEncoder passwordEncoder;
//
//    @Transactional
//    public UserResponse registerUser(UserRequest request) {
//        if (userRepository.existsByEmail(request.getEmail())) {
//            throw new RuntimeException("Email already in use");
//        }
//
//        User user = User.builder()
//                .email(request.getEmail())
//                .password(passwordEncoder.encode(request.getPassword())) // Secure hashing
//                .firstName(request.getFirstName())
//                .lastName(request.getLastName())
//                .role(request.getRole())
//                .build();
//
//        return mapToResponse(userRepository.save(user));
//    }
//
//    public List<UserResponse> getAllUsers() {
//        return userRepository.findAll().stream()
//                .map(this::mapToResponse)
//                .collect(Collectors.toList());
//    }
//
//    public UserResponse getUserById(UUID id) {
//        return userRepository.findById(id)
//                .map(this::mapToResponse)
//                .orElseThrow(() -> new RuntimeException("User not found"));
//    }
//
//    @Transactional
//    public void deleteUser(UUID id) {
//        userRepository.deleteById(id);
//    }
//
//    private UserResponse mapToResponse(User user) {
//        return UserResponse.builder()
//                .id(user.getId())
//                .email(user.getEmail())
//                .firstName(user.getFirstName())
//                .lastName(user.getLastName())
//                .role(user.getRole())
//                .build();
//    }
//}


package com.medibot.healthcare_platform.modules.identity.service;

import com.medibot.healthcare_platform.modules.identity.dto.*;
import com.medibot.healthcare_platform.modules.identity.entity.User;
import com.medibot.healthcare_platform.modules.identity.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Transactional
    public UserResponse registerUser(UserRequest request) {
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new RuntimeException("Email already in use");
        }

        User user = User.builder()
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .age(request.getAge())
                .gender(request.getGender())
                .medicalHistory(request.getMedicalHistory())
                .role(request.getRole())
                .build();

        return mapToResponse(userRepository.save(user));
    }

    public List<UserResponse> getAllUsers() {
        return userRepository.findAll().stream()
                .map(this::mapToResponse)
                .collect(Collectors.toList());
    }

    public UserResponse getUserById(UUID id) {
        return userRepository.findById(id)
                .map(this::mapToResponse)
                .orElseThrow(() -> new RuntimeException("User not found"));
    }

    @Transactional
    public void deleteUser(UUID id) {
        userRepository.deleteById(id);
    }

    private UserResponse mapToResponse(User user) {
        return UserResponse.builder()
                .id(user.getId())
                .email(user.getEmail())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .age(user.getAge())
                .gender(user.getGender())
                .medicalHistory(user.getMedicalHistory())
                .role(user.getRole())
                .build();
    }
}