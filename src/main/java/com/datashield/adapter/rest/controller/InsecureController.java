package com.datashield.adapter.rest.controller;

import com.datashield.adapter.rest.dto.RegisterRequest;
import com.datashield.application.usecase.InsecureUserService;
import com.datashield.domain.model.InsecureUser;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * Controller del ESCENARIO INSEGURO.
 *
 * NOTA: Estos endpoints están intencionalmente desprotegidos
 * para demostrar las vulnerabilidades. No requieren autenticación.
 *
 * En Swagger UI verás claramente qué hace cada endpoint
 * y por qué es peligroso.
 */
@RestController
@RequestMapping("/api/insecure")
@RequiredArgsConstructor
@Tag(name = "🔓 Escenario Inseguro",
     description = "Endpoints sin protección — demostración de vulnerabilidades")
public class InsecureController {

    private final InsecureUserService service;

    @PostMapping("/register")
    @Operation(
        summary = "Registrar usuario (INSEGURO)",
        description = """
            ⚠️ VULNERABILIDADES en este endpoint:
            - Contraseña hasheada con MD5 sin sal
            - PAN almacenado en TEXTO PLANO
            - Sin validación de acceso
            - Datos sensibles se registran en los logs del servidor
            """
    )
    public ResponseEntity<InsecureUser> register(@Valid @RequestBody RegisterRequest req) {
        InsecureUser user = service.register(
            req.getName(), req.getEmail(), req.getPassword(),
            req.getPan(), req.getPhone()
        );
        return ResponseEntity.ok(user);
    }

    @GetMapping("/users")
    @Operation(
        summary = "Listar todos los usuarios (INSEGURO — sin autenticación)",
        description = """
            ⚠️ VULNERABILIDAD CRÍTICA: Sin ningún tipo de autenticación.
            Cualquier petición HTTP devuelve TODOS los usuarios con:
            - PAN en texto plano
            - Hash MD5 de contraseña (crackeable)
            - Email y teléfono completos
            
            Equivalente real: curl http://localhost:8080/api/insecure/users
            """
    )
    public ResponseEntity<List<InsecureUser>> listAll() {
        return ResponseEntity.ok(service.findAll());
    }

    @GetMapping("/users/same-password")
    @Operation(
        summary = "Buscar usuarios con la misma contraseña (Demo MD5 sin sal)",
        description = """
            ⚠️ Solo posible porque MD5 sin sal produce el mismo hash para el mismo password.
            Prueba con: password123
            Verás cuántos usuarios comparten esa contraseña — todos comprometidos a la vez.
            """
    )
    public ResponseEntity<List<InsecureUser>> findByPassword(@RequestParam String password) {
        return ResponseEntity.ok(service.findUsersWithSamePassword(password));
    }
}
