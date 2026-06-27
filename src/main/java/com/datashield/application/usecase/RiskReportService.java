package com.datashield.application.usecase;

import com.datashield.domain.model.RiskReport;
import com.datashield.infrastructure.persistence.entity.InsecureUserEntity;
import com.datashield.infrastructure.persistence.repository.InsecureUserRepository;
import com.datashield.infrastructure.persistence.repository.SecureUserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;

/**
 * Genera el reporte educativo comparativo de riesgo.
 * Es el endpoint más importante del proyecto para la presentación académica.
 */
@Service
@RequiredArgsConstructor
public class RiskReportService {

    private final InsecureUserRepository insecureRepo;
    private final SecureUserRepository secureRepo;

    @Transactional(readOnly = true)
    public RiskReport generateReport() {
        // Toma el primer usuario de cada tabla como muestra
        InsecureUserEntity sample = insecureRepo.findAll()
            .stream().findFirst().orElse(null);

        RiskReport.ScenarioSnapshot insecureSnapshot = buildInsecureSnapshot(sample);
        RiskReport.ScenarioSnapshot secureSnapshot = buildSecureSnapshot();
        List<RiskReport.Vulnerability> vulns = buildVulnerabilityList();

        return RiskReport.builder()
            .generatedAt(LocalDateTime.now())
            .insecureScenario(insecureSnapshot)
            .secureScenario(secureSnapshot)
            .vulnerabilitiesFound(vulns)
            .riskReduction(insecureSnapshot.getRiskScore() - secureSnapshot.getRiskScore())
            .build();
    }

    private RiskReport.ScenarioSnapshot buildInsecureSnapshot(InsecureUserEntity sample) {
        // Muestra datos REALES de la BD insegura — así lo vería un atacante
        String pwdInDb = sample != null ? sample.getPasswordHash() : "482c811da5d5b4bc6d497ffa98491e38";
        String panInDb = sample != null ? sample.getPan() : "4532015112830366";

        return RiskReport.ScenarioSnapshot.builder()
            .scenarioName("Escenario Inseguro")
            .riskScore(95)
            .riskLevel("CRÍTICO")
            .passwordStored(pwdInDb)              // Hash MD5 real
            .panStored(panInDb)                   // PAN real en texto plano
            .emailExposed(sample != null ? sample.getEmail() : "carlos.mendoza@example.com")
            .phoneExposed(sample != null ? sample.getPhone() : "987654321")
            .protections(List.of("Ninguna"))
            .weaknesses(List.of(
                "MD5 sin sal — reversible en segundos con rainbow tables",
                "PAN en texto plano — violación directa de PCI-DSS",
                "Email y teléfono expuestos en API sin filtro",
                "Sin control de acceso — cualquiera puede listar usuarios",
                "Logging de datos sensibles (PAN en logs del servidor)"
            ))
            .build();
    }

    private RiskReport.ScenarioSnapshot buildSecureSnapshot() {
        return RiskReport.ScenarioSnapshot.builder()
            .scenarioName("Escenario Protegido")
            .riskScore(8)
            .riskLevel("BAJO")
            .passwordStored("$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/Lewdm5Q...")
            .panStored("7x9K+mNpQ8vR2cFz... [AES-256-GCM cifrado]")
            .emailExposed("c***@example.com")
            .phoneExposed("9****321")
            .protections(List.of(
                "BCrypt cost=12 con sal automática",
                "AES-256-GCM con IV aleatorio por registro",
                "Data masking en todas las respuestas de API",
                "JWT Bearer token requerido (rol USER o ADMIN)",
                "Logging sin datos sensibles"
            ))
            .weaknesses(List.of(
                "Clave AES en application.yml (mejorable con Key Vault)",
                "Email no cifrado en BD (necesario para autenticación)"
            ))
            .build();
    }

    private List<RiskReport.Vulnerability> buildVulnerabilityList() {
        return List.of(
            RiskReport.Vulnerability.builder()
                .id("EDU-001")
                .name("Contraseña hasheada con MD5 sin sal")
                .severity("CRITICAL")
                .description("MD5 es un algoritmo de hash rápido, no diseñado para contraseñas. "
                    + "Sin sal, dos usuarios con la misma contraseña tienen el mismo hash, "
                    + "y existen bases de datos de millones de hashes pre-calculados (rainbow tables).")
                .attackVector("Un atacante con acceso a la BD puede subir los hashes a "
                    + "CrackStation.net y recuperar la contraseña en segundos para hashes comunes.")
                .mitigation("Usar BCrypt, Argon2 o scrypt. Nunca MD5 o SHA1 para contraseñas.")
                .cweReference("CWE-327: Use of a Broken or Risky Cryptographic Algorithm")
                .build(),

            RiskReport.Vulnerability.builder()
                .id("EDU-002")
                .name("PAN (número de tarjeta) en texto plano")
                .severity("CRITICAL")
                .description("El número de tarjeta se almacena directamente en la base de datos "
                    + "sin ningún tipo de cifrado. Cualquier acceso no autorizado a la BD, "
                    + "backup sin cifrar, o dump SQL expone todos los números de tarjeta.")
                .attackVector("SELECT pan FROM insecure_users; — una sola consulta SQL "
                    + "expone todos los números de tarjeta de todos los usuarios.")
                .mitigation("Cifrar con AES-256-GCM y gestionar claves con HSM o Key Vault. "
                    + "Considerar tokenización para no almacenar el PAN en absoluto.")
                .cweReference("CWE-311: Missing Encryption of Sensitive Data")
                .build(),

            RiskReport.Vulnerability.builder()
                .id("EDU-003")
                .name("API sin autenticación — exposición masiva de datos")
                .severity("HIGH")
                .description("El endpoint /api/insecure/users no requiere autenticación. "
                    + "Cualquier persona con acceso a la red puede listar todos los usuarios "
                    + "con sus emails, teléfonos y hashes de contraseña.")
                .attackVector("curl http://localhost:8080/api/insecure/users — "
                    + "devuelve todos los registros sin ningún token.")
                .mitigation("Requerir JWT Bearer token. Implementar roles RBAC. "
                    + "Aplicar rate limiting para prevenir enumeración masiva.")
                .cweReference("CWE-306: Missing Authentication for Critical Function")
                .build(),

            RiskReport.Vulnerability.builder()
                .id("EDU-004")
                .name("Usuarios con contraseñas idénticas identificables")
                .severity("HIGH")
                .description("Sin sal en el hash MD5, todos los usuarios que usen 'password123' "
                    + "tendrán el mismo hash: 482c811da5d5b4bc6d497ffa98491e38. "
                    + "Un atacante puede comprometer múltiples cuentas con un solo ataque.")
                .attackVector("SELECT email FROM insecure_users WHERE password_hash = '482c811...'; "
                    + "Devuelve todos los usuarios con esa contraseña — acceso masivo.")
                .mitigation("BCrypt genera una sal aleatoria por usuario. Mismo password = "
                    + "hashes completamente diferentes. No hay forma de correlacionar.")
                .cweReference("CWE-760: Use of a One-Way Hash with a Predictable Salt")
                .build(),

            RiskReport.Vulnerability.builder()
                .id("EDU-005")
                .name("Datos sensibles en logs del servidor")
                .severity("MEDIUM")
                .description("El servicio inseguro loguea el PAN completo y el email en texto "
                    + "plano. Los logs del servidor se almacenan en disco, muchas veces sin "
                    + "cifrar, y son accesibles por administradores de sistema o rotados a "
                    + "sistemas de logging centralizados.")
                .attackVector("tail -f application.log | grep PAN — recupera números de tarjeta "
                    + "directamente de los archivos de log sin acceder a la BD.")
                .mitigation("Nunca loguear datos sensibles. Usar masking en logs: "
                    + "log.info('PAN: {}', maskPan(pan)).")
                .cweReference("CWE-532: Insertion of Sensitive Information into Log File")
                .build()
        );
    }
}
