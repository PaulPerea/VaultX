package com.datashield.adapter.rest.controller;

import com.datashield.application.usecase.HackerSimulationService;
import com.datashield.application.usecase.HackerSimulationService.AttackResult;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Controller de la SIMULACIÓN EDUCATIVA DE ATAQUES.
 *
 * ═══════════════════════════════════════════════════════════════
 * AVISO EDUCATIVO
 * ═══════════════════════════════════════════════════════════════
 * Estos endpoints simulan técnicas de ataque en un entorno
 * 100% controlado con datos de prueba en memoria (H2).
 *
 * Propósito: Visualizar el riesgo real de las malas prácticas
 * de seguridad para motivar el uso de las correctas.
 *
 * No se realiza ninguna conexión externa.
 * No se exponen datos reales de producción.
 * ═══════════════════════════════════════════════════════════════
 */
@RestController
@RequestMapping("/api/hacker-sim")
@RequiredArgsConstructor
@Tag(
    name = "💀 Simulación de Ataques (Educativo)",
    description = """
        ⚠️ SOLO FINES EDUCATIVOS — Entorno controlado con datos de prueba en H2.
        Simula técnicas de ataque para demostrar el impacto de malas prácticas de seguridad.
        Todos los ataques corren LOCALMENTE contra la base de datos en memoria.
        """
)
public class HackerSimController {

    private final HackerSimulationService hackerService;

    @GetMapping("/attacks/all")
    @Operation(
        summary = "Ejecutar todos los ataques simulados",
        description = """
            Ejecuta los 5 ataques en secuencia y devuelve los resultados completos.
            Ideal para la demostración en presentación académica.
            """
    )
    public ResponseEntity<List<AttackResult>> runAllAttacks() {
        List<AttackResult> results = List.of(
            hackerService.simulateDatabaseDump(),
            hackerService.simulateRainbowTableAttack(),
            hackerService.simulateCredentialStuffing(),
            hackerService.simulateUnauthorizedAccess(),
            hackerService.simulateLogExfiltration()
        );
        return ResponseEntity.ok(results);
    }

    @GetMapping("/attacks/database-dump")
    @Operation(
        summary = "ATK-001: Database Dump — Acceso directo a la tabla",
        description = "Simula SELECT * FROM insecure_users — muestra todos los PANs en texto plano."
    )
    public ResponseEntity<AttackResult> databaseDump() {
        return ResponseEntity.ok(hackerService.simulateDatabaseDump());
    }

    @GetMapping("/attacks/rainbow-table")
    @Operation(
        summary = "ATK-002: Rainbow Table — Crackeo de MD5",
        description = "Compara los hashes MD5 de la BD contra una tabla pre-calculada y recupera contraseñas."
    )
    public ResponseEntity<AttackResult> rainbowTable() {
        return ResponseEntity.ok(hackerService.simulateRainbowTableAttack());
    }

    @GetMapping("/attacks/credential-stuffing")
    @Operation(
        summary = "ATK-003: Credential Stuffing — Contraseñas reutilizadas",
        description = "Identifica todos los usuarios que comparten la misma contraseña (posible por MD5 sin sal)."
    )
    public ResponseEntity<AttackResult> credentialStuffing() {
        return ResponseEntity.ok(hackerService.simulateCredentialStuffing());
    }

    @GetMapping("/attacks/unauthorized-access")
    @Operation(
        summary = "ATK-004: Acceso no autorizado — API sin protección",
        description = "Obtiene todos los datos de usuarios sin ningún token de autenticación."
    )
    public ResponseEntity<AttackResult> unauthorizedAccess() {
        return ResponseEntity.ok(hackerService.simulateUnauthorizedAccess());
    }

    @GetMapping("/attacks/log-exfiltration")
    @Operation(
        summary = "ATK-005: Log Exfiltration — Datos sensibles en logs",
        description = "Muestra las entradas de log que el servicio inseguro genera con PANs en texto plano."
    )
    public ResponseEntity<AttackResult> logExfiltration() {
        return ResponseEntity.ok(hackerService.simulateLogExfiltration());
    }
}
