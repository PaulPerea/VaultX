package com.datashield.adapter.rest.controller;

import com.datashield.infrastructure.security.JwtService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Controller de autenticación.
 * En una app real, se validaría contra la BD.
 * Aquí usa usuarios hardcodeados para simplificar la demo educativa.
 */
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Tag(name = "🔑 Autenticación", description = "Obtener JWT para acceder al escenario seguro")
public class AuthController {

    private final JwtService jwtService;

    // Credenciales demo hardcodeadas (solo para el proyecto educativo)
    private static final Map<String, String[]> DEMO_USERS = Map.of(
        "user@datashield.com",  new String[]{"user123",  "USER"},
        "admin@datashield.com", new String[]{"admin123", "ADMIN"}
    );

    @PostMapping("/login")
    @Operation(
        summary = "Login y obtener JWT",
        description = """
            Credenciales de demo:
            - user@datashield.com / user123  → rol USER
            - admin@datashield.com / admin123 → rol ADMIN (puede descifrar PANs)
            
            Copia el token y úsalo en el candado 🔒 de Swagger UI.
            """
    )
    public ResponseEntity<?> login(@RequestBody LoginRequest req) {
        String[] userData = DEMO_USERS.get(req.getEmail());

        if (userData == null || !userData[0].equals(req.getPassword())) {
            return ResponseEntity.status(401).body(Map.of(
                "error", "Credenciales inválidas",
                "hint", "Usa: user@datashield.com / user123"
            ));
        }

        String token = jwtService.generateToken(req.getEmail(), userData[1]);

        return ResponseEntity.ok(Map.of(
            "token", token,
            "email", req.getEmail(),
            "role", userData[1],
            "tip", "Copia el token y úsalo como Bearer en los endpoints /api/secure/**"
        ));
    }

    @Data
    public static class LoginRequest {
        private String email;
        private String password;
    }
}
