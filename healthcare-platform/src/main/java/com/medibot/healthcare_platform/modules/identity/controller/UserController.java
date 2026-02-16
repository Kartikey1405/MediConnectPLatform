//package com.medibot.healthcare_platform.modules.identity.controller;
//
//import com.medibot.healthcare_platform.modules.identity.dto.*;
//import com.medibot.healthcare_platform.modules.identity.service.UserService;
//import jakarta.validation.Valid;
//import lombok.RequiredArgsConstructor;
//import org.springframework.http.ResponseEntity;
//import org.springframework.security.access.prepost.PreAuthorize;
//import org.springframework.web.bind.annotation.*;
//
//import java.util.List;
//import java.util.UUID;
//
//@RestController
//@RequestMapping("/api/users")
//@RequiredArgsConstructor
//public class UserController {
//    private final UserService userService;
//
//    @PostMapping("/register")
//    public ResponseEntity<UserResponse> register(@Valid @RequestBody UserRequest request) {
//        return ResponseEntity.ok(userService.registerUser(request));
//    }
//
//    @GetMapping
//    @PreAuthorize("hasRole('ADMIN')")
//    public ResponseEntity<List<UserResponse>> getAllUsers() {
//        return ResponseEntity.ok(userService.getAllUsers());
//    }
//
//    @GetMapping("/{id}")
//    public ResponseEntity<UserResponse> getUser(@PathVariable UUID id) {
//        return ResponseEntity.ok(userService.getUserById(id));
//    }
//
//    @DeleteMapping("/{id}")
//    @PreAuthorize("hasRole('ADMIN')")
//    public ResponseEntity<String> deleteUser(@PathVariable UUID id) {
//        userService.deleteUser(id);
//        return ResponseEntity.ok("User deleted successfully");
//    }
//}

package com.medibot.healthcare_platform.modules.identity.controller;

import com.medibot.healthcare_platform.modules.identity.dto.*;
import com.medibot.healthcare_platform.modules.identity.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;
import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
public class UserController {
    private final UserService userService;

    @PostMapping("/register")
    public ResponseEntity<UserResponse> register(@Valid @RequestBody UserRequest request) {
        return ResponseEntity.ok(userService.registerUser(request));
    }

    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<UserResponse>> getAllUsers() {
        return ResponseEntity.ok(userService.getAllUsers());
    }

    @GetMapping("/{id}")
    public ResponseEntity<UserResponse> getUser(@PathVariable UUID id, Principal principal) {
        UserResponse targetUser = userService.getUserById(id);

        // 1. Get the email of the person currently logged in via the JWT
        String authenticatedEmail = principal.getName();

        // 2. Logic: If the user is NOT the owner, they must be a DOCTOR or ADMIN to see this
        // Note: For a more advanced version, we can check roles here too.
        if (!targetUser.getEmail().equals(authenticatedEmail)) {
            // In a production app, you'd check if (hasRole('DOCTOR')) here.
            // For now, let's block unauthorized cross-patient viewing.
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }

        return ResponseEntity.ok(targetUser);
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<String> deleteUser(@PathVariable UUID id) {
        userService.deleteUser(id);
        return ResponseEntity.ok("User deleted successfully");
    }

    @GetMapping("/me")
    public ResponseEntity<UserResponse> getCurrentUser(Principal principal) {
        // principal.getName() returns the email from the JWT
        UserResponse user = userService.getUserByEmail(principal.getName());
        return ResponseEntity.ok(user);
    }
}