///// /////////////////package com.medibot.healthcare_platform.common.config;
///// /////////////////
///// /////////////////import com.medibot.healthcare_platform.common.util.JwtAuthenticationFilter;
///// /////////////////import lombok.RequiredArgsConstructor;
///// /////////////////import org.springframework.context.annotation.Bean;
///// /////////////////import org.springframework.context.annotation.Configuration;
///// /////////////////import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
///// /////////////////import org.springframework.security.config.annotation.web.builders.HttpSecurity;
///// /////////////////import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
///// /////////////////import org.springframework.security.config.http.SessionCreationPolicy;
///// /////////////////import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
///// /////////////////import org.springframework.security.crypto.password.PasswordEncoder;
///// /////////////////import org.springframework.security.web.SecurityFilterChain;
///// /////////////////import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
///// /////////////////import org.springframework.web.cors.CorsConfiguration;
///// /////////////////import org.springframework.web.cors.CorsConfigurationSource;
///// /////////////////import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
///// /////////////////
///// /////////////////import java.util.Arrays;
///// /////////////////
///// /////////////////@Configuration
///// /////////////////@EnableWebSecurity
///// /////////////////@EnableMethodSecurity // Enables @PreAuthorize("hasRole('...')") on controllers
///// /////////////////@RequiredArgsConstructor
///// /////////////////public class SecurityConfig {
///// /////////////////
///// /////////////////    private final JwtAuthenticationFilter jwtAuthenticationFilter;
///// /////////////////
///// /////////////////    @Bean
///// /////////////////    public PasswordEncoder passwordEncoder() {
///// /////////////////        return new BCryptPasswordEncoder();
///// /////////////////    }
///// /////////////////
///// /////////////////    @Bean
///// /////////////////    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
///// /////////////////        http
///// /////////////////                .csrf(csrf -> csrf.disable()) // Stateless API
///// /////////////////                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
///// /////////////////                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
///// /////////////////                .authorizeHttpRequests(auth -> auth
///// /////////////////                        // 1. PUBLIC ENDPOINTS
///// /////////////////                        .requestMatchers("/api/auth/**", "/api/users/register", "/api/hospitals/**", "/error").permitAll()
///// /////////////////
///// /////////////////                        // 2. DOCTOR SPECIFIC (Slot generation, profile fetching)
///// /////////////////                        .requestMatchers("/api/doctor/**").hasRole("DOCTOR")
///// /////////////////
///// /////////////////                        // 3. SHARED MODULES (Dashboards, Booking, and Live Sessions)
///// /////////////////                        .requestMatchers("/api/bookings/**").hasAnyRole("PATIENT", "DOCTOR", "ADMIN")
///// /////////////////                        .requestMatchers("/api/consultations/**").hasAnyRole("PATIENT", "DOCTOR", "ADMIN")
///// /////////////////
///// /////////////////                        // 4. MEDICAL DATA (Vault & Clinical Review)
///// /////////////////                        .requestMatchers("/api/triage/**").hasRole("PATIENT")
///// /////////////////                        .requestMatchers("/api/records/**").hasAnyRole("PATIENT", "DOCTOR", "ADMIN")
///// /////////////////
///// /////////////////                        // 5. ADMIN CONTROL
///// /////////////////                        .requestMatchers("/api/admin/**").hasRole("ADMIN")
///// /////////////////
///// /////////////////                        // 6. CATCH-ALL
///// /////////////////                        .anyRequest().authenticated()
///// /////////////////                )
///// /////////////////                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
///// /////////////////
///// /////////////////        return http.build();
///// /////////////////    }
///// /////////////////
///// /////////////////    @Bean
///// /////////////////    public CorsConfigurationSource corsConfigurationSource() {
///// /////////////////        CorsConfiguration config = new CorsConfiguration();
///// /////////////////        // Standardizing local development ports for React/Vite
///// /////////////////        config.setAllowedOrigins(Arrays.asList(
///// /////////////////                "http://localhost:3000",
///// /////////////////                "http://localhost:5173",
///// /////////////////                "https://medi-connect-platform.vercel.app"
///// /////////////////        ));
///// /////////////////        // Added PATCH explicitly for the Consultation Notes module
///// /////////////////        config.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
///// /////////////////        config.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type"));
///// /////////////////        config.setAllowCredentials(true);
///// /////////////////
///// /////////////////        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
///// /////////////////        source.registerCorsConfiguration("/**", config);
///// /////////////////        return source;
///// /////////////////    }
///// /////////////////}
///// ///////////////
///// ///////////////
///// ///////////////
///// ///////////////
///// ///////////////
///// ///////////////package com.medibot.healthcare_platform.common.config;
///// ///////////////
///// ///////////////import com.medibot.healthcare_platform.common.util.JwtAuthenticationFilter;
///// ///////////////import lombok.RequiredArgsConstructor;
///// ///////////////import org.springframework.context.annotation.Bean;
///// ///////////////import org.springframework.context.annotation.Configuration;
///// ///////////////import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
///// ///////////////import org.springframework.security.config.annotation.web.builders.HttpSecurity;
///// ///////////////import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
///// ///////////////import org.springframework.security.config.http.SessionCreationPolicy;
///// ///////////////import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
///// ///////////////import org.springframework.security.crypto.password.PasswordEncoder;
///// ///////////////import org.springframework.security.web.SecurityFilterChain;
///// ///////////////import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
///// ///////////////import org.springframework.web.cors.CorsConfiguration;
///// ///////////////import org.springframework.web.cors.CorsConfigurationSource;
///// ///////////////import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
///// ///////////////
///// ///////////////import java.util.Arrays;
///// ///////////////
///// ///////////////@Configuration
///// ///////////////@EnableWebSecurity
///// ///////////////@EnableMethodSecurity
///// ///////////////@RequiredArgsConstructor
///// ///////////////public class SecurityConfig {
///// ///////////////
///// ///////////////    private final JwtAuthenticationFilter jwtAuthenticationFilter;
///// ///////////////
///// ///////////////    @Bean
///// ///////////////    public PasswordEncoder passwordEncoder() {
///// ///////////////        return new BCryptPasswordEncoder();
///// ///////////////    }
///// ///////////////
///// ///////////////    @Bean
///// ///////////////    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
///// ///////////////        http
///// ///////////////                .csrf(csrf -> csrf.disable())
///// ///////////////                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
///// ///////////////                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
///// ///////////////                .authorizeHttpRequests(auth -> auth
///// ///////////////                        // 1. PUBLIC ENDPOINTS
///// ///////////////                        .requestMatchers("/api/auth/**", "/api/users/register", "/api/hospitals/**", "/error").permitAll()
///// ///////////////
///// ///////////////                        // 2. DOCTOR SPECIFIC
///// ///////////////                        .requestMatchers("/api/doctor/**").hasRole("DOCTOR")
///// ///////////////
///// ///////////////                        // 3. SHARED MODULES (Added Maps here)
///// ///////////////                        .requestMatchers("/api/maps/**").hasAnyRole("PATIENT", "ADMIN", "DOCTOR") // <--- FIXED 403 HERE
///// ///////////////                        .requestMatchers("/api/bookings/**").hasAnyRole("PATIENT", "DOCTOR", "ADMIN")
///// ///////////////                        .requestMatchers("/api/consultations/**").hasAnyRole("PATIENT", "DOCTOR", "ADMIN")
///// ///////////////
///// ///////////////                        // 4. MEDICAL DATA
///// ///////////////                        .requestMatchers("/api/triage/**").hasRole("PATIENT")
///// ///////////////                        .requestMatchers("/api/records/**").hasAnyRole("PATIENT", "DOCTOR", "ADMIN")
///// ///////////////
///// ///////////////                        // 5. ADMIN CONTROL
///// ///////////////                        .requestMatchers("/api/admin/**").hasRole("ADMIN")
///// ///////////////
///// ///////////////                        // 6. CATCH-ALL
///// ///////////////                        .anyRequest().authenticated()
///// ///////////////                )
///// ///////////////                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
///// ///////////////
///// ///////////////        return http.build();
///// ///////////////    }
///// ///////////////
///// ///////////////    @Bean
///// ///////////////    public CorsConfigurationSource corsConfigurationSource() {
///// ///////////////        CorsConfiguration config = new CorsConfiguration();
///// ///////////////        config.setAllowedOrigins(Arrays.asList(
///// ///////////////                "http://localhost:3000",
///// ///////////////                "http://localhost:5173",
///// ///////////////                "https://medi-connect-platform.vercel.app",
///// ///////////////                "https://medibotnew.vercel.app" // Added your new frontend link too
///// ///////////////        ));
///// ///////////////        config.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
///// ///////////////        config.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type"));
///// ///////////////        config.setAllowCredentials(true);
///// ///////////////
///// ///////////////        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
///// ///////////////        source.registerCorsConfiguration("/**", config);
///// ///////////////        return source;
///// ///////////////    }
///// ///////////////}
///// /////////////
///// /////////////
///// /////////////
///// /////////////
///// /////////////
///// /////////////
///// /////////////
///// /////////////
///// /////////////
///// /////////////
///// /////////////
///// /////////////
///// /////////////
///// /////////////
///// /////////////
///// /////////////
///// /////////////
///// /////////////
///// /////////////
///// /////////////
///// /////////////
///// /////////////
///// /////////////package com.medibot.healthcare_platform.common.config;
///// /////////////
///// /////////////import com.medibot.healthcare_platform.common.util.JwtAuthenticationFilter;
///// /////////////import lombok.RequiredArgsConstructor;
///// /////////////import org.springframework.context.annotation.Bean;
///// /////////////import org.springframework.context.annotation.Configuration;
///// /////////////import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
///// /////////////import org.springframework.security.config.annotation.web.builders.HttpSecurity;
///// /////////////import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
///// /////////////import org.springframework.security.config.http.SessionCreationPolicy;
///// /////////////import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
///// /////////////import org.springframework.security.crypto.password.PasswordEncoder;
///// /////////////import org.springframework.security.web.SecurityFilterChain;
///// /////////////import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
///// /////////////import org.springframework.web.cors.CorsConfiguration;
///// /////////////import org.springframework.web.cors.CorsConfigurationSource;
///// /////////////import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
///// /////////////
///// /////////////import java.util.Arrays;
///// /////////////
///// /////////////@Configuration
///// /////////////@EnableWebSecurity
///// /////////////@EnableMethodSecurity
///// /////////////@RequiredArgsConstructor
///// /////////////public class SecurityConfig {
///// /////////////
///// /////////////    private final JwtAuthenticationFilter jwtAuthenticationFilter;
///// /////////////
///// /////////////    @Bean
///// /////////////    public PasswordEncoder passwordEncoder() {
///// /////////////        return new BCryptPasswordEncoder();
///// /////////////    }
///// /////////////
///// /////////////    @Bean
///// /////////////    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
///// /////////////        http
///// /////////////                .csrf(csrf -> csrf.disable())
///// /////////////                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
///// /////////////                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
///// /////////////                .authorizeHttpRequests(auth -> auth
///// /////////////                        // 1. PUBLIC ENDPOINTS
///// /////////////                        .requestMatchers("/api/auth/**", "/api/users/register", "/api/hospitals/**", "/error").permitAll()
///// /////////////
///// /////////////                        // 2. DOCTOR SPECIFIC
///// /////////////                        .requestMatchers("/api/doctor/**").hasRole("DOCTOR")
///// /////////////
///// /////////////                        // 3. MAPS & SHARED MODULES
///// /////////////                        // Restricted to PATIENT only as requested; using hasAuthority to fix 403
///// /////////////                        .requestMatchers("/api/maps/**").hasAuthority("PATIENT")
///// /////////////                        .requestMatchers("/api/bookings/**").hasAnyRole("PATIENT", "DOCTOR", "ADMIN")
///// /////////////                        .requestMatchers("/api/consultations/**").hasAnyRole("PATIENT", "DOCTOR", "ADMIN")
///// /////////////
///// /////////////                        // 4. MEDICAL DATA
///// /////////////                        .requestMatchers("/api/triage/**").hasRole("PATIENT")
///// /////////////                        .requestMatchers("/api/records/**").hasAnyRole("PATIENT", "DOCTOR", "ADMIN")
///// /////////////
///// /////////////                        // 5. ADMIN CONTROL
///// /////////////                        .requestMatchers("/api/admin/**").hasRole("ADMIN")
///// /////////////
///// /////////////                        // 6. CATCH-ALL
///// /////////////                        .anyRequest().authenticated()
///// /////////////                )
///// /////////////                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
///// /////////////
///// /////////////        return http.build();
///// /////////////    }
///// /////////////
///// /////////////    @Bean
///// /////////////    public CorsConfigurationSource corsConfigurationSource() {
///// /////////////        CorsConfiguration config = new CorsConfiguration();
///// /////////////        config.setAllowedOrigins(Arrays.asList(
///// /////////////                "http://localhost:3000",
///// /////////////                "http://localhost:5173",
///// /////////////                "https://medi-connect-platform.vercel.app",
///// /////////////                "https://medibotnew.vercel.app"
///// /////////////        ));
///// /////////////        config.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
///// /////////////        config.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type"));
///// /////////////        config.setAllowCredentials(true);
///// /////////////
///// /////////////        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
///// /////////////        source.registerCorsConfiguration("/**", config);
///// /////////////        return source;
///// /////////////    }
///// /////////////}
///// ///////////
///// ///////////
///// ///////////
///// ///////////
///// ///////////
///// ///////////
///// ///////////
///// ///////////
///// ///////////
///// ///////////
///// ///////////
///// ///////////package com.medibot.healthcare_platform.common.config;
///// ///////////
///// ///////////import com.medibot.healthcare_platform.common.util.JwtAuthenticationFilter;
///// ///////////import lombok.RequiredArgsConstructor;
///// ///////////import org.springframework.context.annotation.Bean;
///// ///////////import org.springframework.context.annotation.Configuration;
///// ///////////import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
///// ///////////import org.springframework.security.config.annotation.web.builders.HttpSecurity;
///// ///////////import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
///// ///////////import org.springframework.security.config.http.SessionCreationPolicy;
///// ///////////import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
///// ///////////import org.springframework.security.crypto.password.PasswordEncoder;
///// ///////////import org.springframework.security.web.SecurityFilterChain;
///// ///////////import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
///// ///////////import org.springframework.web.cors.CorsConfiguration;
///// ///////////import org.springframework.web.cors.CorsConfigurationSource;
///// ///////////import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
///// ///////////
///// ///////////import java.util.Arrays;
///// ///////////
///// ///////////@Configuration
///// ///////////@EnableWebSecurity
///// ///////////@EnableMethodSecurity
///// ///////////@RequiredArgsConstructor
///// ///////////public class SecurityConfig {
///// ///////////
///// ///////////    private final JwtAuthenticationFilter jwtAuthenticationFilter;
///// ///////////
///// ///////////    @Bean
///// ///////////    public PasswordEncoder passwordEncoder() {
///// ///////////        return new BCryptPasswordEncoder();
///// ///////////    }
///// ///////////
///// ///////////    @Bean
///// ///////////    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
///// ///////////        http
///// ///////////                .csrf(csrf -> csrf.disable())
///// ///////////                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
///// ///////////                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
///// ///////////                .authorizeHttpRequests(auth -> auth
///// ///////////                        // 1. PUBLIC ENDPOINTS
///// ///////////                        .requestMatchers("/api/auth/**", "/api/users/register", "/api/hospitals/**", "/error").permitAll()
///// ///////////
///// ///////////                        // 2. DOCTOR SPECIFIC
///// ///////////                        .requestMatchers("/api/doctor/**").hasRole("DOCTOR")
///// ///////////
///// ///////////                        // 3. MAPS & SHARED MODULES
///// ///////////                        // hasRole("PATIENT") looks for "ROLE_PATIENT", which matches our filter perfectly
///// ///////////                        .requestMatchers("/api/maps/**").hasRole("PATIENT")
///// ///////////                        .requestMatchers("/api/bookings/**").hasAnyRole("PATIENT", "DOCTOR", "ADMIN")
///// ///////////                        .requestMatchers("/api/consultations/**").hasAnyRole("PATIENT", "DOCTOR", "ADMIN")
///// ///////////
///// ///////////                        // 4. MEDICAL DATA
///// ///////////                        .requestMatchers("/api/triage/**").hasRole("PATIENT")
///// ///////////                        .requestMatchers("/api/records/**").hasAnyRole("PATIENT", "DOCTOR", "ADMIN")
///// ///////////
///// ///////////                        // 5. ADMIN CONTROL
///// ///////////                        .requestMatchers("/api/admin/**").hasRole("ADMIN")
///// ///////////
///// ///////////                        // 6. CATCH-ALL
///// ///////////                        .anyRequest().authenticated()
///// ///////////                )
///// ///////////                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
///// ///////////
///// ///////////        return http.build();
///// ///////////    }
///// ///////////
///// ///////////    @Bean
///// ///////////    public CorsConfigurationSource corsConfigurationSource() {
///// ///////////        CorsConfiguration config = new CorsConfiguration();
///// ///////////        config.setAllowedOrigins(Arrays.asList(
///// ///////////                "http://localhost:3000",
///// ///////////                "http://localhost:5173",
///// ///////////                "https://medi-connect-platform.vercel.app",
///// ///////////                "https://medibotnew.vercel.app"
///// ///////////        ));
///// ///////////        config.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
///// ///////////        config.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type"));
///// ///////////        config.setAllowCredentials(true);
///// ///////////
///// ///////////        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
///// ///////////        source.registerCorsConfiguration("/**", config);
///// ///////////        return source;
///// ///////////    }
///// ///////////}
///// /////////
///// /////////
///// /////////
///// /////////
///// /////////package com.medibot.healthcare_platform.common.config;
///// /////////
///// /////////import com.medibot.healthcare_platform.common.util.JwtAuthenticationFilter;
///// /////////import lombok.RequiredArgsConstructor;
///// /////////import org.springframework.context.annotation.Bean;
///// /////////import org.springframework.context.annotation.Configuration;
///// /////////import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
///// /////////import org.springframework.security.config.annotation.web.builders.HttpSecurity;
///// /////////import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
///// /////////import org.springframework.security.config.http.SessionCreationPolicy;
///// /////////import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
///// /////////import org.springframework.security.crypto.password.PasswordEncoder;
///// /////////import org.springframework.security.web.SecurityFilterChain;
///// /////////import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
///// /////////import org.springframework.web.cors.CorsConfiguration;
///// /////////import org.springframework.web.cors.CorsConfigurationSource;
///// /////////import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
///// /////////
///// /////////import java.util.Arrays;
///// /////////
///// /////////@Configuration
///// /////////@EnableWebSecurity
///// /////////@EnableMethodSecurity
///// /////////@RequiredArgsConstructor
///// /////////public class SecurityConfig {
///// /////////
///// /////////    private final JwtAuthenticationFilter jwtAuthenticationFilter;
///// /////////
///// /////////    @Bean
///// /////////    public PasswordEncoder passwordEncoder() {
///// /////////        return new BCryptPasswordEncoder();
///// /////////    }
///// /////////
///// /////////    @Bean
///// /////////    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
///// /////////        http
///// /////////                .csrf(csrf -> csrf.disable())
///// /////////                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
///// /////////                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
///// /////////                .authorizeHttpRequests(auth -> auth
///// /////////                        // 1. PUBLIC ENDPOINTS
///// /////////                        .requestMatchers("/api/auth/**", "/api/users/register", "/api/hospitals/**", "/error").permitAll()
///// /////////
///// /////////                        // 2. DOCTOR SPECIFIC
///// /////////                        .requestMatchers("/api/doctor/**").hasRole("DOCTOR")
///// /////////
///// /////////                        // 3. MAPS & SHARED MODULES (Restricted to Patient only)
///// /////////                        .requestMatchers("/api/maps/**").hasRole("PATIENT")
///// /////////                        .requestMatchers("/api/bookings/**").hasAnyRole("PATIENT", "DOCTOR", "ADMIN")
///// /////////                        .requestMatchers("/api/consultations/**").hasAnyRole("PATIENT", "DOCTOR", "ADMIN")
///// /////////
///// /////////                        // 4. MEDICAL DATA
///// /////////                        .requestMatchers("/api/triage/**").hasRole("PATIENT")
///// /////////                        .requestMatchers("/api/records/**").hasAnyRole("PATIENT", "DOCTOR", "ADMIN")
///// /////////
///// /////////                        // 5. ADMIN CONTROL
///// /////////                        .requestMatchers("/api/admin/**").hasRole("ADMIN")
///// /////////
///// /////////                        // 6. CATCH-ALL
///// /////////                        .anyRequest().authenticated()
///// /////////                )
///// /////////                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
///// /////////
///// /////////        return http.build();
///// /////////    }
///// /////////
///// /////////    @Bean
///// /////////    public CorsConfigurationSource corsConfigurationSource() {
///// /////////        CorsConfiguration config = new CorsConfiguration();
///// /////////        config.setAllowedOrigins(Arrays.asList(
///// /////////                "http://localhost:3000",
///// /////////                "http://localhost:5173",
///// /////////                "https://medi-connect-platform.vercel.app",
///// /////////                "https://medibotnew.vercel.app"
///// /////////        ));
///// /////////        config.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
///// /////////        config.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type"));
///// /////////        config.setAllowCredentials(true);
///// /////////
///// /////////        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
///// /////////        source.registerCorsConfiguration("/**", config);
///// /////////        return source;
///// /////////    }
///// /////////}
///// ///////
///// ///////
///// ///////
///// ///////
///// ///////package com.medibot.healthcare_platform.common.config;
///// ///////
///// ///////import com.medibot.healthcare_platform.common.util.JwtAuthenticationFilter;
///// ///////import lombok.RequiredArgsConstructor;
///// ///////import org.springframework.context.annotation.Bean;
///// ///////import org.springframework.context.annotation.Configuration;
///// ///////import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
///// ///////import org.springframework.security.config.annotation.web.builders.HttpSecurity;
///// ///////import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
///// ///////import org.springframework.security.config.http.SessionCreationPolicy;
///// ///////import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
///// ///////import org.springframework.security.crypto.password.PasswordEncoder;
///// ///////import org.springframework.security.web.SecurityFilterChain;
///// ///////import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
///// ///////import org.springframework.web.cors.CorsConfiguration;
///// ///////import org.springframework.web.cors.CorsConfigurationSource;
///// ///////import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
///// ///////
///// ///////import java.util.Arrays;
///// ///////
///// ///////@Configuration
///// ///////@EnableWebSecurity
///// ///////@EnableMethodSecurity
///// ///////@RequiredArgsConstructor
///// ///////public class SecurityConfig {
///// ///////
///// ///////    private final JwtAuthenticationFilter jwtAuthenticationFilter;
///// ///////
///// ///////    @Bean
///// ///////    public PasswordEncoder passwordEncoder() {
///// ///////        return new BCryptPasswordEncoder();
///// ///////    }
///// ///////
///// ///////    @Bean
///// ///////    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
///// ///////        http
///// ///////                .csrf(csrf -> csrf.disable())
///// ///////                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
///// ///////                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
///// ///////                .authorizeHttpRequests(auth -> auth
///// ///////                        // 1. PUBLIC ENDPOINTS
///// ///////                        .requestMatchers("/api/auth/**", "/api/users/register", "/api/hospitals/**", "/error").permitAll()
///// ///////
///// ///////                        // 2. DOCTOR SPECIFIC
///// ///////                        .requestMatchers("/api/doctor/**").hasRole("DOCTOR")
///// ///////
///// ///////                        // 3. MAPS & SHARED MODULES
///// ///////                        // matches "ROLE_PATIENT" generated by the filter
///// ///////                        .requestMatchers("/api/maps/**").hasRole("PATIENT")
///// ///////                        .requestMatchers("/api/bookings/**").hasAnyRole("PATIENT", "DOCTOR", "ADMIN")
///// ///////                        .requestMatchers("/api/consultations/**").hasAnyRole("PATIENT", "DOCTOR", "ADMIN")
///// ///////
///// ///////                        // 4. MEDICAL DATA
///// ///////                        .requestMatchers("/api/triage/**").hasRole("PATIENT")
///// ///////                        .requestMatchers("/api/records/**").hasAnyRole("PATIENT", "DOCTOR", "ADMIN")
///// ///////
///// ///////                        // 5. ADMIN CONTROL
///// ///////                        .requestMatchers("/api/admin/**").hasRole("ADMIN")
///// ///////
///// ///////                        // 6. CATCH-ALL
///// ///////                        .anyRequest().authenticated()
///// ///////                )
///// ///////                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
///// ///////
///// ///////        return http.build();
///// ///////    }
///// ///////
///// ///////    @Bean
///// ///////    public CorsConfigurationSource corsConfigurationSource() {
///// ///////        CorsConfiguration config = new CorsConfiguration();
///// ///////        config.setAllowedOrigins(Arrays.asList(
///// ///////                "http://localhost:3000",
///// ///////                "http://localhost:5173",
///// ///////                "https://medi-connect-platform.vercel.app",
///// ///////                "https://medibotnew.vercel.app"
///// ///////        ));
///// ///////        config.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
///// ///////        config.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type"));
///// ///////        config.setAllowCredentials(true);
///// ///////
///// ///////        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
///// ///////        source.registerCorsConfiguration("/**", config);
///// ///////        return source;
///// ///////    }
///// ///////}
///// /////
///// /////
///// /////
///// /////
///// /////
///// /////
///// /////
///// /////
///// /////
///// /////
///// /////
///// /////
///// /////
///// /////
///// /////
///// /////
///// /////package com.medibot.healthcare_platform.common.config;
///// /////
///// /////import com.medibot.healthcare_platform.common.util.JwtAuthenticationFilter;
///// /////import lombok.RequiredArgsConstructor;
///// /////import org.springframework.context.annotation.Bean;
///// /////import org.springframework.context.annotation.Configuration;
///// /////import org.springframework.security.config.annotation.web.builders.HttpSecurity;
///// /////import org.springframework.security.config.http.SessionCreationPolicy;
///// /////import org.springframework.security.web.SecurityFilterChain;
///// /////import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
///// /////import org.springframework.web.cors.CorsConfiguration;
///// /////import org.springframework.web.cors.CorsConfigurationSource;
///// /////import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
///// /////import java.util.Arrays;
///// /////
///// /////@Configuration
///// /////@RequiredArgsConstructor
///// /////public class SecurityConfig {
///// /////
///// /////    private final JwtAuthenticationFilter jwtAuthenticationFilter;
///// /////
///// /////    @Bean
///// /////    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
///// /////        http
///// /////                .csrf(csrf -> csrf.disable())
///// /////                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
///// /////                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
///// /////                .authorizeHttpRequests(auth -> auth
///// /////                        // 🔥 BYPASSING SECURITY FOR MAPS TO DEBUG
///// /////                        .requestMatchers("/api/auth/**", "/api/users/register", "/api/hospitals/**", "/api/maps/**", "/error").permitAll()
///// /////
///// /////                        .requestMatchers("/api/doctor/**").hasRole("DOCTOR")
///// /////                        .requestMatchers("/api/bookings/**", "/api/consultations/**").hasAnyRole("PATIENT", "DOCTOR", "ADMIN")
///// /////                        .anyRequest().authenticated()
///// /////                )
///// /////                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
///// /////
///// /////        return http.build();
///// /////    }
///// /////
///// /////    @Bean
///// /////    public CorsConfigurationSource corsConfigurationSource() {
///// /////        CorsConfiguration config = new CorsConfiguration();
///// /////        // Allow common development origins
///// /////        config.setAllowedOrigins(Arrays.asList("http://localhost:3000", "http://localhost:5173"));
///// /////        config.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
///// /////        config.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type", "Cache-Control"));
///// /////        config.setAllowCredentials(true);
///// /////        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
///// /////        source.registerCorsConfiguration("/**", config);
///// /////        return source;
///// /////    }
///// /////}
///// ///
///// ///
///// ///
///// ///
///// ///
///// ///
///// ///
///// ///
///// ///
///// ///
///// ///
///// ///
///// ///
///// ///
///// ///
///// ///
///// ///package com.medibot.healthcare_platform.common.config;
///// ///
///// ///import com.medibot.healthcare_platform.common.util.JwtAuthenticationFilter;
///// ///import lombok.RequiredArgsConstructor;
///// ///import org.springframework.context.annotation.Bean;
///// ///import org.springframework.context.annotation.Configuration;
///// ///import org.springframework.security.config.annotation.web.builders.HttpSecurity;
///// ///import org.springframework.security.config.http.SessionCreationPolicy;
///// ///import org.springframework.security.web.SecurityFilterChain;
///// ///import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
///// ///import org.springframework.web.cors.CorsConfiguration;
///// ///import org.springframework.web.cors.CorsConfigurationSource;
///// ///import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
///// ///
///// ///import java.util.Arrays;
///// ///import java.util.Collections;
///// ///
///// ///@Configuration
///// ///@RequiredArgsConstructor
///// ///public class SecurityConfig {
///// ///
///// ///    private final JwtAuthenticationFilter jwtAuthenticationFilter;
///// ///
///// ///    @Bean
///// ///    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
///// ///        http
///// ///                .csrf(csrf -> csrf.disable())
///// ///                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
///// ///                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
///// ///                .authorizeHttpRequests(auth -> auth
///// ///                        // 1. PUBLIC GATES: Open Maps for debugging and Auth for login
///// ///                        .requestMatchers("/api/auth/**", "/api/users/register", "/api/maps/**", "/api/hospitals/**", "/error").permitAll()
///// ///
///// ///                        // 2. PROTECTED GATES
///// ///                        .requestMatchers("/api/doctor/**").hasRole("DOCTOR")
///// ///                        .requestMatchers("/api/bookings/**", "/api/consultations/**").hasAnyRole("PATIENT", "DOCTOR", "ADMIN")
///// ///
///// ///                        // 3. CATCH-ALL
///// ///                        .anyRequest().authenticated()
///// ///                )
///// ///                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
///// ///
///// ///        return http.build();
///// ///    }
///// ///
///// ///    @Bean
///// ///    public CorsConfigurationSource corsConfigurationSource() {
///// ///        CorsConfiguration config = new CorsConfiguration();
///// ///        // Be explicit about the origin to avoid "Allow-Origin" errors
///// ///        config.setAllowedOrigins(Arrays.asList("http://localhost:3000", "http://localhost:5173"));
///// ///        config.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"));
///// ///        config.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type", "Cache-Control"));
///// ///        config.setAllowCredentials(true);
///// ///        config.setExposedHeaders(Collections.singletonList("Authorization"));
///// ///
///// ///        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
///// ///        source.registerCorsConfiguration("/**", config);
///// ///        return source;
///// ///    }
///// ///}
///// /
///// /
///// /
///// /
///// /
///// /
///// /
///// /
///// /
///// /
///// /
///// /
///// /
///// /
///// /
///// /
///// /
///// /
///// /package com.medibot.healthcare_platform.common.config;
///// /
///// /import com.medibot.healthcare_platform.common.util.JwtAuthenticationFilter;
///// /import lombok.RequiredArgsConstructor;
///// /import org.springframework.context.annotation.Bean;
///// /import org.springframework.context.annotation.Configuration;
///// /import org.springframework.security.config.annotation.web.builders.HttpSecurity;
///// /import org.springframework.security.config.http.SessionCreationPolicy;
///// /import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
///// /import org.springframework.security.crypto.password.PasswordEncoder;
///// /import org.springframework.security.web.SecurityFilterChain;
///// /import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
///// /import org.springframework.web.cors.CorsConfiguration;
///// /import org.springframework.web.cors.CorsConfigurationSource;
///// /import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
///// /
///// /import java.util.Arrays;
///// /
///// /@Configuration
///// /@RequiredArgsConstructor
///// /public class SecurityConfig {
///// /
///// /    private final JwtAuthenticationFilter jwtAuthenticationFilter;
///// /
///// /    // 🔥 THIS WAS MISSING: This allows UserService to work and the app to start!
///// /    @Bean
///// /    public PasswordEncoder passwordEncoder() {
///// /        return new BCryptPasswordEncoder();
///// /    }
///// /
///// /    @Bean
///// /    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
///// /        http
///// /                .csrf(csrf -> csrf.disable())
///// /                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
///// /                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
///// /                .authorizeHttpRequests(auth -> auth
///// /                        // 1. PUBLIC GATES: Open Maps for debugging and Auth for login
///// /                        .requestMatchers("/api/auth/**", "/api/users/register", "/api/maps/**", "/api/hospitals/**", "/error").permitAll()
///// /
///// /                        // 2. PROTECTED GATES
///// /                        .requestMatchers("/api/doctor/**").hasRole("DOCTOR")
///// /                        .requestMatchers("/api/bookings/**", "/api/consultations/**").hasAnyRole("PATIENT", "DOCTOR", "ADMIN")
///// /
///// /                        // 3. CATCH-ALL
///// /                        .anyRequest().authenticated()
///// /                )
///// /                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
///// /
///// /        return http.build();
///// /    }
///// /
///// /    @Bean
///// /    public CorsConfigurationSource corsConfigurationSource() {
///// /        CorsConfiguration config = new CorsConfiguration();
///// /        config.setAllowedOrigins(Arrays.asList("http://localhost:3000", "http://localhost:5173"));
///// /        config.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"));
///// /        config.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type", "Cache-Control"));
///// /        config.setAllowCredentials(true);
///// /
///// /        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
///// /        source.registerCorsConfiguration("/**", config);
///// /        return source;
///// /    }
///// /}
////
////
////
////
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
////                        .requestMatchers("/api/auth/**", "/api/users/register", "/api/hospitals/**", "/error").permitAll()
////
////                        // 2. SECURED MAPS (Strictly for Patients)
////                        .requestMatchers("/api/maps/**").hasRole("PATIENT")
////
////                        // 3. OTHER MODULES
////                        .requestMatchers("/api/doctor/**").hasRole("DOCTOR")
////                        .requestMatchers("/api/bookings/**", "/api/consultations/**", "/api/records/**").hasAnyRole("PATIENT", "DOCTOR", "ADMIN")
////                        .requestMatchers("/api/triage/**").hasRole("PATIENT")
////                        .requestMatchers("/api/admin/**").hasRole("ADMIN")
////
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
////        config.setAllowedOrigins(Arrays.asList("http://localhost:3000", "http://localhost:5173"));
////        config.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
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
//@EnableMethodSecurity
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
//                        // 1. Public Endpoints
//                        .requestMatchers("/api/auth/**", "/api/users/register", "/api/hospitals/**", "/error").permitAll()
//
//                        // 2. Maps - Use hasRole to match the "ROLE_" prefix from your filter
//                        .requestMatchers("/api/maps/**").hasRole("PATIENT")
//
//                        // 3. Other Modules
//                        .requestMatchers("/api/doctor/**").hasRole("DOCTOR")
//                        .requestMatchers("/api/bookings/**", "/api/consultations/**", "/api/records/**").hasAnyRole("PATIENT", "DOCTOR", "ADMIN")
//                        .requestMatchers("/api/triage/**").hasRole("PATIENT")
//                        .requestMatchers("/api/admin/**").hasRole("ADMIN")
//
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
//        config.setAllowedOrigins(Arrays.asList("http://localhost:3000", "http://localhost:5173"));
//        config.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
//        config.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type", "Cache-Control"));
//        config.setAllowCredentials(true);
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
import java.util.List;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
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
                .csrf(csrf -> csrf.disable())
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        // 1. Public Endpoints — OPTIONS must be here to allow CORS preflight
                        .requestMatchers(
                                org.springframework.http.HttpMethod.OPTIONS, "/**"
                        ).permitAll()

                        .requestMatchers("/api/auth/**", "/api/users/register", "/api/hospitals/**", "/error").permitAll()

                        // 2. Maps - Patient only
                        .requestMatchers("/api/maps/**").hasRole("PATIENT")

                                // In your existing SecurityConfig filterChain, add this line
// alongside the other .requestMatchers() rules:

                                .requestMatchers("/api/report-insight/**").hasRole("PATIENT")

                        // 3. Other Modules
                        .requestMatchers("/api/doctor/**").hasRole("DOCTOR")
                        .requestMatchers("/api/bookings/**", "/api/consultations/**", "/api/records/**").hasAnyRole("PATIENT", "DOCTOR", "ADMIN")
                        .requestMatchers("/api/triage/**").hasRole("PATIENT")
                        .requestMatchers("/api/admin/**").hasRole("ADMIN")

                        .anyRequest().authenticated()
                )
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(Arrays.asList(
                "http://localhost:3000",
                "http://localhost:5173",
                "https://medi-connect-platform.vercel.app",
                "https://medibotnew.vercel.app"
        ));
        config.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
        // FIX: Must include every header your frontend sends
        config.setAllowedHeaders(Arrays.asList(
                "Authorization",
                "Content-Type",
                "Cache-Control",
                "X-Requested-With",
                "Accept",
                "Origin",
                "Access-Control-Request-Method",
                "Access-Control-Request-Headers"
        ));
        config.setExposedHeaders(List.of("Authorization"));
        config.setAllowCredentials(true);
        // Cache preflight for 1 hour to reduce repeated OPTIONS calls
        config.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }
}