package com.datashield.adapter.rest.controller;

import com.datashield.adapter.rest.dto.RegisterRequest;
import com.datashield.application.usecase.SecureUserService;
import com.datashield.domain.model.SecureUser;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * Controller del ESCENARIO SEGURO.
 * Requiere JWT Bearer token para todos los endpoints.
 */
@RestController
@RequestMapping("/api/secure")
@RequiredArgsConstructor
@Tag(name = "🔐 Escenario Seguro",
     description = "Endpoints protegidos — BCrypt + AES-256-GCM + JWT + Data Masking")
@SecurityRequirement(name = "bearerAuth")
public class SecureController {

    private final SecureUserService service;

    @PostMapping("/register")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    @Operation(
        summary = "Registrar usuario (SEGURO)",
        description = """
            ✅ PROTECCIONES aplicadas:
            - Requiere JWT válido (Bearer token)
            - BCrypt cost=12 con sal automática para la contraseña
            - PAN cifrado con AES-256-GCM + IV aleatorio
            - Teléfono ofuscado antes de persistir
            - Logging seguro (sin datos sensibles)
            """
    )
    public ResponseEntity<SecureUser> register(@Valid @RequestBody RegisterRequest req) {
        SecureUser user = service.register(
            req.getName(), req.getEmail(), req.getPassword(),
            req.getPan(), req.getPhone()
        );
        return ResponseEntity.ok(user);
    }

    @GetMapping("/users")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    @Operation(
        summary = "Listar usuarios (datos ofuscados)",
        description = """
            ✅ Requiere autenticación JWT.
            Los datos retornados están ofuscados:
            - PAN: **** **** **** 1234
            - Email: c***@example.com
            - Password: [PROTEGIDO]
            """
    )
    public ResponseEntity<List<SecureUser>> listAll() {
        return ResponseEntity.ok(service.findAll());
    }

    @GetMapping("/users/{id}/pan")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(
        summary = "Descifrar PAN de usuario (solo ADMIN)",
        description = """
            ✅ Requiere rol ADMIN — operación de auditoría controlada.
            En producción, esta operación requeriría:
            - 2FA adicional
            - Registro en audit log inmutable
            - Justificación de negocio
            """
    )
    public ResponseEntity<Map<String, String>> decryptPan(@PathVariable Long id) {
        String pan = service.decryptPanForAudit(id);
        return ResponseEntity.ok(Map.of(
            "userId", String.valueOf(id),
            "pan_decrypted", pan,
            "warning", "Operación auditada. Solo para roles ADMIN autorizados."
        ));
    }
}
