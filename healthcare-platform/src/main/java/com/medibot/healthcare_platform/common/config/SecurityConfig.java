//////////////package com.medibot.healthcare_platform.common.config;
//////////////
//////////////import org.springframework.context.annotation.Bean;
//////////////import org.springframework.context.annotation.Configuration;
//////////////import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
//////////////import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//////////////import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
//////////////import org.springframework.security.config.http.SessionCreationPolicy;
//////////////import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
//////////////import org.springframework.security.crypto.password.PasswordEncoder;
//////////////import org.springframework.security.web.SecurityFilterChain;
//////////////
//////////////@Configuration
//////////////@EnableWebSecurity
//////////////@EnableMethodSecurity // Allows @PreAuthorize for Admin/Doctor checks
//////////////public class SecurityConfig {
//////////////
//////////////    @Bean
//////////////    public PasswordEncoder passwordEncoder() {
//////////////        return new BCryptPasswordEncoder();
//////////////    }
//////////////
//////////////    @Bean
//////////////    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
//////////////        http.csrf(csrf -> csrf.disable()) // Stateless API
//////////////                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
//////////////                .authorizeHttpRequests(auth ->
//////////////                        auth.requestMatchers("/api/auth/**").permitAll() // Login/Signup is public
//////////////                                .requestMatchers("/api/admin/**").hasRole("ADMIN") // Hospital setup is Admin only
//////////////                                .anyRequest().authenticated()
//////////////                );
//////////////
//////////////        return http.build();
//////////////    }
//////////////}
////////////
////////////
////////////package com.medibot.healthcare_platform.common.config;
////////////
////////////import org.springframework.context.annotation.Bean;
////////////import org.springframework.context.annotation.Configuration;
////////////import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
////////////import org.springframework.security.config.annotation.web.builders.HttpSecurity;
////////////import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
////////////import org.springframework.security.config.http.SessionCreationPolicy;
////////////import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
////////////import org.springframework.security.crypto.password.PasswordEncoder;
////////////import org.springframework.security.web.SecurityFilterChain;
////////////import org.springframework.web.cors.CorsConfiguration;
////////////import org.springframework.web.cors.CorsConfigurationSource;
////////////import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
////////////
////////////import java.util.Arrays;
////////////
////////////@Configuration
////////////@EnableWebSecurity
////////////@EnableMethodSecurity // Enables @PreAuthorize("hasRole('ADMIN')") used in your controllers
////////////public class SecurityConfig {
////////////
////////////    @Bean
////////////    public PasswordEncoder passwordEncoder() {
////////////        return new BCryptPasswordEncoder();
////////////    }
////////////
////////////    @Bean
////////////    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
////////////        http
////////////                .csrf(csrf -> csrf.disable()) // Disabled for stateless JWT-based APIs
////////////                .cors(cors -> cors.configurationSource(corsConfigurationSource())) // Essential for Lovable/Frontend connection
////////////                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
////////////                .authorizeHttpRequests(auth -> auth
////////////                        // 1. Fully Public Endpoints
////////////                        .requestMatchers("/api/auth/**").permitAll()
////////////                        .requestMatchers("/api/hospitals/**").permitAll() // Allows /api/hospitals and /api/hospitals/sos for everyone
////////////
////////////                        // 2. Role-Based Endpoints (Backup to your Controller-level @PreAuthorize)
////////////                        .requestMatchers("/api/admin/**").hasRole("ADMIN")
////////////                        .requestMatchers("/api/doctor/**").hasRole("DOCTOR")
////////////
////////////                        // 3. All other features (Triage, Video Calls, Vault) require login
////////////                        .anyRequest().authenticated()
////////////                );
////////////
////////////        return http.build();
////////////    }
////////////
////////////    /**
////////////     * CORS Configuration: Allows your frontend (Lovable/React) to talk to the Backend.
////////////     */
////////////    @Bean
////////////    public CorsConfigurationSource corsConfigurationSource() {
////////////        CorsConfiguration configuration = new CorsConfiguration();
////////////        configuration.setAllowedOrigins(Arrays.asList("http://localhost:5173", "https://your-lovable-app-url.com")); // Add your production URL
////////////        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
////////////        configuration.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type"));
////////////        configuration.setAllowCredentials(true);
////////////
////////////        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
////////////        source.registerCorsConfiguration("/**", configuration);
////////////        return source;
////////////    }
////////////}
//////////
//////////
//////////
//////////package com.medibot.healthcare_platform.common.config;
//////////
//////////import lombok.RequiredArgsConstructor;
//////////import org.springframework.context.annotation.Bean;
//////////import org.springframework.context.annotation.Configuration;
//////////import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
//////////import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//////////import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
//////////import org.springframework.security.config.http.SessionCreationPolicy;
//////////import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
//////////import org.springframework.security.crypto.password.PasswordEncoder;
//////////import org.springframework.security.web.SecurityFilterChain;
//////////import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
//////////import org.springframework.web.cors.CorsConfiguration;
//////////import org.springframework.web.cors.CorsConfigurationSource;
//////////import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
//////////
//////////import java.util.Arrays;
//////////
//////////@Configuration
//////////@EnableWebSecurity
//////////@EnableMethodSecurity // Enables @PreAuthorize support
//////////@RequiredArgsConstructor
//////////public class SecurityConfig {
//////////
//////////    private final com.medibot.healthcare_platform.common.util.JwtAuthenticationFilter jwtAuthenticationFilter;
//////////
//////////    @Bean
//////////    public PasswordEncoder passwordEncoder() {
//////////        return new BCryptPasswordEncoder();
//////////    }
//////////
////////////    @Bean
////////////    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
////////////        http
////////////                .csrf(csrf -> csrf.disable()) // Stateless API
////////////                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
////////////                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
////////////                .authorizeHttpRequests(auth -> auth
////////////                        .requestMatchers("/api/auth/**").permitAll()
////////////                        .requestMatchers("/api/hospitals/**").permitAll() // Public Discovery
////////////                        .requestMatchers("/api/admin/**").hasRole("ADMIN") // Backup check
////////////                        .anyRequest().authenticated()
////////////                )
////////////                // ADDED: Register the JWT Filter here!
////////////                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
////////////
////////////        return http.build();
////////////    }
//////////
//////////    @Bean
//////////    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
//////////        http
//////////                .csrf(csrf -> csrf.disable()) // Keep this disabled for Postman/Stateless APIs
//////////                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
//////////                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
//////////                .authorizeHttpRequests(auth -> auth
//////////                        // 1. PUBLIC ENDPOINTS
//////////                        .requestMatchers("/api/auth/**").permitAll()
//////////                        .requestMatchers("/api/users/register").permitAll() // ADD THIS: Matches your UserController path
//////////                        .requestMatchers("/api/hospitals/**").permitAll()
//////////                        .requestMatchers("/error").permitAll() // ADD THIS: Prevents 403 on internal error redirects
//////////
//////////                        // 2. PROTECTED ENDPOINTS
//////////                        .requestMatchers("/api/admin/**").hasRole("ADMIN")
//////////                        .anyRequest().authenticated()
//////////                )
//////////                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
//////////
//////////        return http.build();
//////////    }
//////////
//////////    @Bean
//////////    public CorsConfigurationSource corsConfigurationSource() {
//////////        CorsConfiguration config = new CorsConfiguration();
//////////        config.setAllowedOrigins(Arrays.asList("http://localhost:5173", "https://your-lovable-app.com"));
//////////        config.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
//////////        config.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type"));
//////////        config.setAllowCredentials(true);
//////////
//////////        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
//////////        source.registerCorsConfiguration("/**", config);
//////////        return source;
//////////    }
//////////}
////////
////////package com.medibot.healthcare_platform.common.config;
////////
////////import com.medibot.healthcare_platform.common.util.JwtAuthenticationFilter;
////////import lombok.RequiredArgsConstructor;
////////import org.springframework.context.annotation.Bean;
////////import org.springframework.context.annotation.Configuration;
////////import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
////////import org.springframework.security.config.annotation.web.builders.HttpSecurity;
////////import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
////////import org.springframework.security.config.http.SessionCreationPolicy;
////////import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
////////import org.springframework.security.crypto.password.PasswordEncoder;
////////import org.springframework.security.web.SecurityFilterChain;
////////import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
////////import org.springframework.web.cors.CorsConfiguration;
////////import org.springframework.web.cors.CorsConfigurationSource;
////////import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
////////import java.util.Arrays;
////////
////////@Configuration
////////@EnableWebSecurity
////////@EnableMethodSecurity
////////@RequiredArgsConstructor
////////public class SecurityConfig {
////////
////////    private final JwtAuthenticationFilter jwtAuthenticationFilter;
////////
////////    @Bean
////////    public PasswordEncoder passwordEncoder() {
////////        return new BCryptPasswordEncoder();
////////    }
////////
////////    @Bean
////////    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
////////        http
////////                .csrf(csrf -> csrf.disable()) // Required for stateless API testing
////////                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
////////                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
////////                .authorizeHttpRequests(auth -> auth
////////                        // Publicly accessible endpoints
////////                        .requestMatchers("/api/auth/**").permitAll()
////////                        .requestMatchers("/api/users/register").permitAll()
////////                        .requestMatchers("/api/hospitals/**").permitAll()
////////                        .requestMatchers("/error").permitAll()
////////                        // Inside SecurityConfig.java -> filterChain method
////////                        // Inside your Security Filter Chain
////////                        .requestMatchers("/api/records/patient/**").hasRole("PATIENT")
////////
////////                        // Protected endpoints (Requires JWT)
////////                        .requestMatchers("/api/admin/**").hasRole("ADMIN")
////////                        .anyRequest().authenticated()
////////                )
////////                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
////////
////////        return http.build();
////////    }
////////
////////    @Bean
////////    public CorsConfigurationSource corsConfigurationSource() {
////////        CorsConfiguration config = new CorsConfiguration();
////////        config.setAllowedOrigins(Arrays.asList("http://localhost:3000","http://localhost:5173", "https://your-lovable-app.com"));
////////        config.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
////////        config.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type"));
////////        config.setAllowCredentials(true);
////////
////////        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
////////        source.registerCorsConfiguration("/**", config);
////////        return source;
////////    }
//////package com.medibot.healthcare_platform.common.config;
//////
//////import com.medibot.healthcare_platform.common.util.JwtAuthenticationFilter;
//////import lombok.RequiredArgsConstructor;
//////import org.springframework.context.annotation.Bean;
//////import org.springframework.context.annotation.Configuration;
//////import org.springframework.http.HttpMethod;
//////import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
//////import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//////import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
//////import org.springframework.security.config.http.SessionCreationPolicy;
//////import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
//////import org.springframework.security.crypto.password.PasswordEncoder;
//////import org.springframework.security.web.SecurityFilterChain;
//////import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
//////import org.springframework.web.cors.CorsConfiguration;
//////import org.springframework.web.cors.CorsConfigurationSource;
//////import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
//////import java.util.Arrays;
//////
//////@Configuration
//////@EnableWebSecurity
//////@EnableMethodSecurity
//////@RequiredArgsConstructor
//////public class SecurityConfig {
//////
//////    private final JwtAuthenticationFilter jwtAuthenticationFilter;
//////
//////    @Bean
//////    public PasswordEncoder passwordEncoder() {
//////        return new BCryptPasswordEncoder();
//////    }
//////
//////    @Bean
//////    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
//////        http
//////                .csrf(csrf -> csrf.disable())
//////                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
//////                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
//////                .authorizeHttpRequests(auth -> auth
//////                        // 1. PUBLIC ENDPOINTS
//////                        .requestMatchers("/api/auth/**").permitAll()
//////                        .requestMatchers("/api/users/register").permitAll()
//////                        .requestMatchers("/api/hospitals/**").permitAll()
//////                        .requestMatchers("/error").permitAll()
//////
//////                        // 2. PATIENT SPECIFIC (Order is important!)
//////                        // Explicitly permit both GET (history) and POST (save triage) for patients
//////                        .requestMatchers("/api/records/patient/**").hasAnyRole("PATIENT", "ADMIN")
//////
//////                        // 3. ADMIN SPECIFIC
//////                        .requestMatchers("/api/admin/**").hasRole("ADMIN")
//////
//////                        // 4. CATCH-ALL
//////                        .anyRequest().authenticated()
//////                )
//////                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
//////
//////        return http.build();
//////    }
//////
//////    @Bean
//////    public CorsConfigurationSource corsConfigurationSource() {
//////        CorsConfiguration config = new CorsConfiguration();
//////        // Added localhost:3000 to ensure your specific React port is allowed
//////        config.setAllowedOrigins(Arrays.asList(
//////                "http://localhost:3000",
//////                "http://localhost:5173",
//////                "https://your-lovable-app.com"
//////        ));
//////        config.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
//////        config.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type"));
//////        config.setAllowCredentials(true);
//////
//////        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
//////        source.registerCorsConfiguration("/**", config);
//////        return source;
//////    }
//////}
////
////
////
////package com.medibot.healthcare_platform.common.config;
////
////import com.medibot.healthcare_platform.common.util.JwtAuthenticationFilter;
////import lombok.RequiredArgsConstructor;
////import org.springframework.context.annotation.Bean;
////import org.springframework.context.annotation.Configuration;
////import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
////import org.springframework.security.config.annotation.web.builders.HttpSecurity;
////import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
////import org.springframework.security.config.http.SessionCreationPolicy;
////import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
////import org.springframework.security.crypto.password.PasswordEncoder;
////import org.springframework.security.web.SecurityFilterChain;
////import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
////import org.springframework.web.cors.CorsConfiguration;
////import org.springframework.web.cors.CorsConfigurationSource;
////import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
////
////import java.util.Arrays;
////
////@Configuration
////@EnableWebSecurity
////@EnableMethodSecurity
////@RequiredArgsConstructor
////public class SecurityConfig {
////
////    private final JwtAuthenticationFilter jwtAuthenticationFilter;
////
////    @Bean
////    public PasswordEncoder passwordEncoder() {
////        return new BCryptPasswordEncoder();
////    }
////
////    @Bean
////    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
////        http
////                .csrf(csrf -> csrf.disable())
////                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
////                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
////                .authorizeHttpRequests(auth -> auth
////                        // 1. PUBLIC ENDPOINTS
////                        .requestMatchers("/api/auth/**").permitAll()
////                        .requestMatchers("/api/users/register").permitAll()
////                        .requestMatchers("/api/hospitals/**").permitAll()
////                        .requestMatchers("/error").permitAll()
////
////                        // 2. TRIAGE HISTORY & RECALLS (The "Timeline")
////                        .requestMatchers("/api/triage/history/**").hasRole("PATIENT")
////
////                        // 3. MEDICAL RECORDS & CLOUDINARY UPLOADS (The "Vault")
////                        .requestMatchers("/api/records/upload/**").hasRole("PATIENT")
////                        .requestMatchers("/api/records/patient/**").hasAnyRole("PATIENT", "ADMIN")
////
////                        // 4. ADMIN & DOCTOR SPECIFIC
////                        .requestMatchers("/api/admin/**").hasRole("ADMIN")
////                        .requestMatchers("/api/doctor/**").hasRole("DOCTOR")
////
////                        // 5. CATCH-ALL
////                        .anyRequest().authenticated()
////                )
////                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
////
////        return http.build();
////    }
////
////    @Bean
////    public CorsConfigurationSource corsConfigurationSource() {
////        CorsConfiguration config = new CorsConfiguration();
////        config.setAllowedOrigins(Arrays.asList(
////                "http://localhost:3000",
////                "http://localhost:5173",
////                "https://your-lovable-app-url.com"
////        ));
////        config.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
////        config.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type"));
////        config.setAllowCredentials(true);
////
////        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
////        source.registerCorsConfiguration("/**", config);
////        return source;
////    }
////}
//
//
//
//
//package com.medibot.healthcare_platform.common.config;
//
//import com.medibot.healthcare_platform.common.util.JwtAuthenticationFilter;
//import lombok.RequiredArgsConstructor;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
//import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
//import org.springframework.security.config.http.SessionCreationPolicy;
//import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
//import org.springframework.security.crypto.password.PasswordEncoder;
//import org.springframework.security.web.SecurityFilterChain;
//import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
//import org.springframework.web.cors.CorsConfiguration;
//import org.springframework.web.cors.CorsConfigurationSource;
//import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
//
//import java.util.Arrays;
//
//@Configuration
//@EnableWebSecurity
//@EnableMethodSecurity // Critical for @PreAuthorize support
//@RequiredArgsConstructor
//public class SecurityConfig {
//
//    private final JwtAuthenticationFilter jwtAuthenticationFilter;
//
//    @Bean
//    public PasswordEncoder passwordEncoder() {
//        return new BCryptPasswordEncoder();
//    }
//
//    @Bean
//    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
//        http
//                .csrf(csrf -> csrf.disable())
//                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
//                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
//                .authorizeHttpRequests(auth -> auth
//                        // 1. PUBLIC PATHS
//                        .requestMatchers("/api/auth/**", "/api/users/register", "/api/hospitals/**", "/error").permitAll()
//
//                        // 2. BOOKING MODULE: Shared access for Dashboard synchronization
//                        .requestMatchers("/api/bookings/**").hasAnyRole("PATIENT", "DOCTOR", "ADMIN")
//
//                        // 3. CONSULTATION MODULE: Handshake and Medical Notes
//                        .requestMatchers("/api/consultations/**").hasAnyRole("PATIENT", "DOCTOR", "ADMIN")
//
//                        // 4. MODULE SPECIFIC ACCESS
//                        .requestMatchers("/api/triage/**").hasRole("PATIENT")
//                        .requestMatchers("/api/records/**").hasAnyRole("PATIENT", "DOCTOR", "ADMIN")
//                        .requestMatchers("/api/admin/**").hasRole("ADMIN")
//
//                        // 5. CATCH-ALL
//                        .anyRequest().authenticated()
//                )
//                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
//
//        return http.build();
//    }
//
//    @Bean
//    public CorsConfigurationSource corsConfigurationSource() {
//        CorsConfiguration config = new CorsConfiguration();
//        config.setAllowedOrigins(Arrays.asList(
//                "http://localhost:3000",
//                "http://localhost:5173",
//                "https://your-lovable-app-url.com"
//        ));
//        config.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
//        config.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type"));
//        config.setAllowCredentials(true);
//
//        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
//        source.registerCorsConfiguration("/**", config);
//        return source;
//    }
//}








package com.medibot.healthcare_platform.common.config;

import com.medibot.healthcare_platform.common.util.JwtAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity // Enables @PreAuthorize("hasRole('...')") on controllers
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable()) // Stateless API
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        // 1. PUBLIC ENDPOINTS
                        .requestMatchers("/api/auth/**", "/api/users/register", "/api/hospitals/**", "/error").permitAll()

                        // 2. DOCTOR SPECIFIC (Slot generation, profile fetching)
                        .requestMatchers("/api/doctor/**").hasRole("DOCTOR")

                        // 3. SHARED MODULES (Dashboards, Booking, and Live Sessions)
                        .requestMatchers("/api/bookings/**").hasAnyRole("PATIENT", "DOCTOR", "ADMIN")
                        .requestMatchers("/api/consultations/**").hasAnyRole("PATIENT", "DOCTOR", "ADMIN")

                        // 4. MEDICAL DATA (Vault & Clinical Review)
                        .requestMatchers("/api/triage/**").hasRole("PATIENT")
                        .requestMatchers("/api/records/**").hasAnyRole("PATIENT", "DOCTOR", "ADMIN")

                        // 5. ADMIN CONTROL
                        .requestMatchers("/api/admin/**").hasRole("ADMIN")

                        // 6. CATCH-ALL
                        .anyRequest().authenticated()
                )
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        // Standardizing local development ports for React/Vite
        config.setAllowedOrigins(Arrays.asList(
                "http://localhost:3000",
                "http://localhost:5173",
                "https://your-lovable-app-url.com"
        ));
        // Added PATCH explicitly for the Consultation Notes module
        config.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type"));
        config.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }
}