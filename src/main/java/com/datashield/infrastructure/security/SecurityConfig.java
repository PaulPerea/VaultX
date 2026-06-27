package com.datashield.infrastructure.security;

import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * Configuración de Spring Security.
 *
 * REGLAS DE ACCESO:
 * - /api/insecure/**   → PÚBLICO (intencionalmente sin auth — demo vulnerabilidad)
 * - /api/hacker-sim/** → PÚBLICO (demo educativa)
 * - /api/compare/**    → PÚBLICO (para la presentación)
 * - /api/secure/**     → REQUIERE JWT (USER o ADMIN)
 * - /api/auth/**       → PÚBLICO (login para obtener token)
 * - /h2-console/**     → PÚBLICO (para ver la BD en la demo)
 * - /swagger-ui/**     → PÚBLICO (documentación)
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
@SecurityScheme(
    name = "bearerAuth",
    type = SecuritySchemeType.HTTP,
    scheme = "bearer",
    bearerFormat = "JWT"
)
public class SecurityConfig {

    private final JwtAuthFilter jwtAuthFilter;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
            .csrf(AbstractHttpConfigurer::disable)
            .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth
                // Endpoints públicos para la demo
                .requestMatchers("/api/insecure/**").permitAll()
                .requestMatchers("/api/hacker-sim/**").permitAll()
                .requestMatchers("/api/compare/**").permitAll()
                .requestMatchers("/api/auth/**").permitAll()
                // Herramientas de desarrollo
                .requestMatchers("/h2-console/**").permitAll()
                .requestMatchers("/swagger-ui/**", "/swagger-ui.html",
                                 "/api-docs/**", "/v3/api-docs/**").permitAll()
                // Endpoints protegidos
                .requestMatchers("/api/secure/**").authenticated()
                .anyRequest().authenticated()
            )
            // Permite que H2 Console use frames (solo para demo)
            .headers(h -> h.frameOptions(f -> f.sameOrigin()))
            .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
            .build();
    }
}
