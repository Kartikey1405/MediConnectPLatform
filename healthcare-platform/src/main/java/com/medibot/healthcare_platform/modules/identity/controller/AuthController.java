//package com.medibot.healthcare_platform.modules.identity.controller;
//
//import com.medibot.healthcare_platform.modules.identity.dto.LoginRequest;
//import com.medibot.healthcare_platform.modules.identity.dto.AuthResponse;
//import com.medibot.healthcare_platform.modules.identity.service.AuthService;
//import jakarta.validation.Valid;
//import lombok.RequiredArgsConstructor;
//import org.springframework.http.ResponseEntity;
//import org.springframework.web.bind.annotation.*;
//
//@RestController
//@RequestMapping("/api/auth")
//@RequiredArgsConstructor
//public class AuthController {
//
//    private final AuthService authService;
//
//    @PostMapping("/login")
//    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest request) {
//        return ResponseEntity.ok(authService.login(request));
//    }
//}


package com.medibot.healthcare_platform.modules.identity.controller;

import com.medibot.healthcare_platform.modules.identity.dto.LoginRequest;
import com.medibot.healthcare_platform.modules.identity.dto.AuthResponse;
import com.medibot.healthcare_platform.modules.identity.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest request) {
        return ResponseEntity.ok(authService.login(request));
    }
}