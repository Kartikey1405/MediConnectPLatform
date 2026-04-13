////////////package com.medibot.healthcare_platform.common.util;
////////////
////////////import com.medibot.healthcare_platform.common.util.JwtUtils;
////////////import jakarta.servlet.FilterChain;
////////////import jakarta.servlet.ServletException;
////////////import jakarta.servlet.http.HttpServletRequest;
////////////import jakarta.servlet.http.HttpServletResponse;
////////////import lombok.RequiredArgsConstructor;
////////////import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
////////////import org.springframework.security.core.authority.SimpleGrantedAuthority;
////////////import org.springframework.security.core.context.SecurityContextHolder;
////////////import org.springframework.stereotype.Component;
////////////import org.springframework.web.filter.OncePerRequestFilter;
////////////
////////////import java.io.IOException;
////////////import java.util.List;
////////////
////////////@Component
////////////@RequiredArgsConstructor
////////////public class JwtAuthenticationFilter extends OncePerRequestFilter {
////////////
////////////    private final JwtUtils jwtUtils;
////////////
////////////    @Override
////////////    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
////////////            throws ServletException, IOException {
////////////
////////////        String authHeader = request.getHeader("Authorization");
////////////        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
////////////            filterChain.doFilter(request, response);
////////////            return;
////////////        }
////////////
////////////        String token = authHeader.substring(7);
////////////        if (jwtUtils.validateJwtToken(token)) {
////////////            String email = jwtUtils.getUserNameFromJwtToken(token);
////////////            String role = jwtUtils.getRoleFromToken(token);
////////////
////////////            // Add ROLE_ prefix so Spring Security matches @PreAuthorize correctly
////////////            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
////////////                    email, null, List.of(new SimpleGrantedAuthority("ROLE_" + role))
////////////            );
////////////
////////////            SecurityContextHolder.getContext().setAuthentication(authentication);
////////////        }
////////////        filterChain.doFilter(request, response);
////////////    }
////////////}
//////////
//////////
//////////
//////////
//////////package com.medibot.healthcare_platform.common.util;
//////////
//////////import jakarta.servlet.FilterChain;
//////////import jakarta.servlet.ServletException;
//////////import jakarta.servlet.http.HttpServletRequest;
//////////import jakarta.servlet.http.HttpServletResponse;
//////////import lombok.RequiredArgsConstructor;
//////////import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
//////////import org.springframework.security.core.authority.SimpleGrantedAuthority;
//////////import org.springframework.security.core.context.SecurityContextHolder;
//////////import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
//////////import org.springframework.stereotype.Component;
//////////import org.springframework.web.filter.OncePerRequestFilter;
//////////
//////////import java.io.IOException;
//////////import java.util.List;
//////////
//////////@Component
//////////@RequiredArgsConstructor
//////////public class JwtAuthenticationFilter extends OncePerRequestFilter {
//////////
//////////    private final JwtUtils jwtUtils;
//////////
//////////    @Override
//////////    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
//////////            throws ServletException, IOException {
//////////
//////////        String authHeader = request.getHeader("Authorization");
//////////
//////////        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
//////////            filterChain.doFilter(request, response);
//////////            return;
//////////        }
//////////
//////////        String token = authHeader.substring(7);
//////////
//////////        if (jwtUtils.validateJwtToken(token)) {
//////////            String email = jwtUtils.getUserNameFromJwtToken(token);
//////////            String role = jwtUtils.getRoleFromToken(token);
//////////
//////////            if (email != null && SecurityContextHolder.getContext().getAuthentication() == null) {
//////////                // We add the ROLE_ prefix here to follow Spring Security conventions
//////////                SimpleGrantedAuthority authority = new SimpleGrantedAuthority("ROLE_" + role);
//////////
//////////                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
//////////                        email, null, List.of(authority)
//////////                );
//////////
//////////                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
//////////                SecurityContextHolder.getContext().setAuthentication(authentication);
//////////            }
//////////        }
//////////        filterChain.doFilter(request, response);
//////////    }
//////////}
////////
////////
////////package com.medibot.healthcare_platform.common.util;
////////
////////import jakarta.servlet.FilterChain;
////////import jakarta.servlet.ServletException;
////////import jakarta.servlet.http.HttpServletRequest;
////////import jakarta.servlet.http.HttpServletResponse;
////////import lombok.RequiredArgsConstructor;
////////import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
////////import org.springframework.security.core.authority.SimpleGrantedAuthority;
////////import org.springframework.security.core.context.SecurityContextHolder;
////////import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
////////import org.springframework.stereotype.Component;
////////import org.springframework.web.filter.OncePerRequestFilter;
////////
////////import java.io.IOException;
////////import java.util.List;
////////
////////@Component
////////@RequiredArgsConstructor
////////public class JwtAuthenticationFilter extends OncePerRequestFilter {
////////
////////    private final JwtUtils jwtUtils;
////////
////////    @Override
////////    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
////////            throws ServletException, IOException {
////////
////////        String authHeader = request.getHeader("Authorization");
////////
////////        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
////////            filterChain.doFilter(request, response);
////////            return;
////////        }
////////
////////        String token = authHeader.substring(7);
////////
////////        if (jwtUtils.validateJwtToken(token)) {
////////            String email = jwtUtils.getUserNameFromJwtToken(token);
////////            String role = jwtUtils.getRoleFromToken(token);
////////
////////            if (email != null && SecurityContextHolder.getContext().getAuthentication() == null) {
////////                // Standardizing role to Uppercase and adding ROLE_ prefix
////////                String formattedRole = "ROLE_" + role.toUpperCase().trim();
////////                SimpleGrantedAuthority authority = new SimpleGrantedAuthority(formattedRole);
////////
////////                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
////////                        email, null, List.of(authority)
////////                );
////////
////////                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
////////                SecurityContextHolder.getContext().setAuthentication(authentication);
////////            }
////////        }
////////        filterChain.doFilter(request, response);
////////    }
////////}
//////
//////
//////
//////
//////package com.medibot.healthcare_platform.common.util;
//////
//////import jakarta.servlet.FilterChain;
//////import jakarta.servlet.ServletException;
//////import jakarta.servlet.http.HttpServletRequest;
//////import jakarta.servlet.http.HttpServletResponse;
//////import lombok.RequiredArgsConstructor;
//////import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
//////import org.springframework.security.core.authority.SimpleGrantedAuthority;
//////import org.springframework.security.core.context.SecurityContextHolder;
//////import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
//////import org.springframework.stereotype.Component;
//////import org.springframework.web.filter.OncePerRequestFilter;
//////
//////import java.io.IOException;
//////import java.util.List;
//////
//////@Component
//////@RequiredArgsConstructor
//////public class JwtAuthenticationFilter extends OncePerRequestFilter {
//////
//////    private final JwtUtils jwtUtils;
//////
//////    @Override
//////    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
//////            throws ServletException, IOException {
//////
//////        String authHeader = request.getHeader("Authorization");
//////
//////        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
//////            filterChain.doFilter(request, response);
//////            return;
//////        }
//////
//////        String token = authHeader.substring(7);
//////
//////        if (jwtUtils.validateJwtToken(token)) {
//////            String email = jwtUtils.getUserNameFromJwtToken(token);
//////            String role = jwtUtils.getRoleFromToken(token);
//////
//////            if (email != null && SecurityContextHolder.getContext().getAuthentication() == null) {
//////                // Standardizing role to Uppercase and adding ROLE_ prefix
//////                String formattedRole = "ROLE_" + role.toUpperCase().trim();
//////                SimpleGrantedAuthority authority = new SimpleGrantedAuthority(formattedRole);
//////
//////                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
//////                        email, null, List.of(authority)
//////                );
//////
//////                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
//////                SecurityContextHolder.getContext().setAuthentication(authentication);
//////            }
//////        }
//////        filterChain.doFilter(request, response);
//////    }
//////}
////
////
////package com.medibot.healthcare_platform.common.util;
////
////import jakarta.servlet.FilterChain;
////import jakarta.servlet.ServletException;
////import jakarta.servlet.http.HttpServletRequest;
////import jakarta.servlet.http.HttpServletResponse;
////import lombok.RequiredArgsConstructor;
////import lombok.extern.slf4j.Slf4j;
////import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
////import org.springframework.security.core.authority.SimpleGrantedAuthority;
////import org.springframework.security.core.context.SecurityContextHolder;
////import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
////import org.springframework.stereotype.Component;
////import org.springframework.web.filter.OncePerRequestFilter;
////
////import java.io.IOException;
////import java.util.List;
////
////@Component
////@RequiredArgsConstructor
////@Slf4j // Add this to see debug logs in IntelliJ
////public class JwtAuthenticationFilter extends OncePerRequestFilter {
////
////    private final JwtUtils jwtUtils;
////
////    @Override
////    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
////            throws ServletException, IOException {
////
////        String authHeader = request.getHeader("Authorization");
////
////        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
////            filterChain.doFilter(request, response);
////            return;
////        }
////
////        String token = authHeader.substring(7);
////
////        if (jwtUtils.validateJwtToken(token)) {
////            String email = jwtUtils.getUserNameFromJwtToken(token);
////            String role = jwtUtils.getRoleFromToken(token);
////
////            // 1. CRITICAL NULL CHECK: Prevent crash if token is old
////            if (email != null && role != null && SecurityContextHolder.getContext().getAuthentication() == null) {
////
////                String formattedRole = "ROLE_" + role.toUpperCase().trim();
////                log.info("Authorizing user: {} with role: {}", email, formattedRole);
////
////                SimpleGrantedAuthority authority = new SimpleGrantedAuthority(formattedRole);
////
////                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
////                        email, null, List.of(authority)
////                );
////
////                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
////                SecurityContextHolder.getContext().setAuthentication(authentication);
////            } else if (role == null) {
////                log.warn("Access Denied: Token for user {} has no role claim. Please log out and back in.", email);
////            }
////        }
////        filterChain.doFilter(request, response);
////    }
////}
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//package com.medibot.healthcare_platform.common.util;
//
//import jakarta.servlet.FilterChain;
//import jakarta.servlet.ServletException;
//import jakarta.servlet.http.HttpServletRequest;
//import jakarta.servlet.http.HttpServletResponse;
//import lombok.RequiredArgsConstructor;
//import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
//import org.springframework.security.core.authority.SimpleGrantedAuthority;
//import org.springframework.security.core.context.SecurityContextHolder;
//import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
//import org.springframework.stereotype.Component;
//import org.springframework.web.filter.OncePerRequestFilter;
//
//import java.io.IOException;
//import java.util.List;
//
//@Component
//@RequiredArgsConstructor
//public class JwtAuthenticationFilter extends OncePerRequestFilter {
//
//    private final JwtUtils jwtUtils;
//
//    @Override
//    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
//            throws ServletException, IOException {
//
//        String authHeader = request.getHeader("Authorization");
//
//        // If no token, just move to the next filter (this allows login to proceed)
//        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
//            filterChain.doFilter(request, response);
//            return;
//        }
//
//        String token = authHeader.substring(7);
//
//        try {
//            if (jwtUtils.validateJwtToken(token)) {
//                String email = jwtUtils.getUserNameFromJwtToken(token);
//                String role = jwtUtils.getRoleFromToken(token);
//
//                if (email != null && role != null && SecurityContextHolder.getContext().getAuthentication() == null) {
//                    SimpleGrantedAuthority authority = new SimpleGrantedAuthority("ROLE_" + role.toUpperCase().trim());
//                    UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(email, null, List.of(authority));
//                    auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
//                    SecurityContextHolder.getContext().setAuthentication(auth);
//                }
//            }
//        } catch (Exception e) {
//            // Silently fail if token is malformed to prevent login block
//            logger.error("Could not set user authentication", e);
//        }
//
//        filterChain.doFilter(request, response);
//    }
//}


package com.medibot.healthcare_platform.common.util;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtUtils jwtUtils;

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        // FIX: Skip JWT processing entirely for OPTIONS preflight requests
        // Without this, OPTIONS hits the filter chain unauthenticated and gets 403
        return "OPTIONS".equalsIgnoreCase(request.getMethod());
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        String authHeader = request.getHeader("Authorization");

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = authHeader.substring(7);

        try {
            if (jwtUtils.validateJwtToken(token)) {
                String email = jwtUtils.getUserNameFromJwtToken(token);
                String role = jwtUtils.getRoleFromToken(token);

                if (email != null && role != null
                        && SecurityContextHolder.getContext().getAuthentication() == null) {

                    // ROLE_ prefix is added here; hasRole("PATIENT") in SecurityConfig
                    // also adds ROLE_ internally — they must match exactly
                    String formattedRole = "ROLE_" + role.toUpperCase().trim();
                    SimpleGrantedAuthority authority = new SimpleGrantedAuthority(formattedRole);

                    UsernamePasswordAuthenticationToken auth =
                            new UsernamePasswordAuthenticationToken(email, null, List.of(authority));
                    auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(auth);
                }
            }
        } catch (Exception e) {
            logger.error("JWT authentication failed: " + e.getMessage());
        }

        filterChain.doFilter(request, response);
    }
}