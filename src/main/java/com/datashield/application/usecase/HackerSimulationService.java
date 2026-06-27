package com.datashield.application.usecase;

import com.datashield.domain.port.CryptoPort;
import com.datashield.infrastructure.persistence.entity.InsecureUserEntity;
import com.datashield.infrastructure.persistence.repository.InsecureUserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

/**
 * ════════════════════════════════════════════════════════════════
 * SIMULACIÓN EDUCATIVA DE ATAQUE — DataShield Lab
 * ════════════════════════════════════════════════════════════════
 *
 * Este servicio simula, en un entorno controlado y seguro,
 * las técnicas que un atacante podría usar contra el ESCENARIO INSEGURO.
 *
 * IMPORTANTE:
 * - Todo corre contra datos de prueba en H2 en memoria
 * - No hay conexión a sistemas externos
 * - El objetivo es VISUALIZAR el riesgo, no causar daño
 * - Cada método documenta la técnica y su mitigación
 *
 * USO: Solo a través del endpoint /api/hacker-sim/**
 *      que requiere rol ADMIN y está marcado en Swagger como educativo.
 * ════════════════════════════════════════════════════════════════
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class HackerSimulationService {

    private final InsecureUserRepository insecureRepo;
    private final CryptoPort cryptoPort;

    /**
     * ATAQUE 1: Database Dump Simulation
     *
     * Simula lo que un atacante ve si obtiene acceso de lectura a la BD
     * (ej: via SQL Injection, backup filtrado, acceso interno malicioso).
     *
     * Técnica real: SELECT * FROM insecure_users;
     */
    @Transactional(readOnly = true)
    public AttackResult simulateDatabaseDump() {
        log.warn("[HACKER-SIM] Ejecutando: Database Dump Attack");

        List<InsecureUserEntity> allUsers = insecureRepo.findAll();

        List<Map<String, String>> exposedData = allUsers.stream().map(u -> {
            Map<String, String> row = new LinkedHashMap<>();
            row.put("id", String.valueOf(u.getId()));
            row.put("name", u.getName());              // Nombre completo expuesto
            row.put("email", u.getEmail());            // Email expuesto
            row.put("password_md5", u.getPasswordHash()); // Hash crackeable
            row.put("pan", u.getPan());               // ← PAN EN TEXTO PLANO
            row.put("phone", u.getPhone());
            return row;
        }).collect(Collectors.toList());

        return AttackResult.builder()
            .attackId("ATK-001")
            .attackName("Database Dump — Acceso directo a tabla")
            .technique("SELECT * FROM insecure_users;")
            .severity("CRÍTICO")
            .successful(true)
            .dataExposed(exposedData)
            .recordsCompromised(allUsers.size())
            .executedAt(LocalDateTime.now())
            .explanation("Con acceso de lectura a la base de datos (por ejemplo, "
                + "a través de SQL Injection en otro endpoint, un backup filtrado, "
                + "o un administrador malicioso), el atacante obtiene TODOS los datos "
                + "en texto plano en una sola consulta.")
            .realWorldImpact("Robo de identidad, fraude con tarjetas de crédito, "
                + "venta de datos en mercados clandestinos (dark web).")
            .howToPrevent("Cifrar columnas sensibles (AES-256-GCM). "
                + "Principio de mínimo privilegio en BD. "
                + "Tokenización de PANs. Auditoría de accesos.")
            .build();
    }

    /**
     * ATAQUE 2: MD5 Rainbow Table Attack
     *
     * Simula el crackeo de contraseñas MD5 mediante una mini rainbow table.
     * En la realidad, herramientas como Hashcat o CrackStation tienen
     * MILES DE MILLONES de hashes pre-calculados.
     */
    @Transactional(readOnly = true)
    public AttackResult simulateRainbowTableAttack() {
        log.warn("[HACKER-SIM] Ejecutando: MD5 Rainbow Table Attack");

        // Mini rainbow table educativa — contraseñas comunes y sus MD5
        Map<String, String> rainbowTable = buildEducationalRainbowTable();

        List<InsecureUserEntity> users = insecureRepo.findAll();
        List<Map<String, String>> crackedPasswords = new ArrayList<>();

        for (InsecureUserEntity user : users) {
            String hash = user.getPasswordHash();
            String crackedPwd = rainbowTable.get(hash);
            if (crackedPwd != null) {
                Map<String, String> cracked = new LinkedHashMap<>();
                cracked.put("email", user.getEmail());
                cracked.put("md5_hash_in_db", hash);
                cracked.put("password_recovered", crackedPwd);  // ← PASSWORD RECUPERADA
                cracked.put("status", "✓ CRACKEADA");
                crackedPasswords.add(cracked);
            }
        }

        return AttackResult.builder()
            .attackId("ATK-002")
            .attackName("MD5 Rainbow Table — Crackeo de contraseñas")
            .technique("Comparar hash MD5 de la BD contra tabla pre-calculada de millones de hashes")
            .severity("CRÍTICO")
            .successful(!crackedPasswords.isEmpty())
            .dataExposed(crackedPasswords)
            .recordsCompromised(crackedPasswords.size())
            .executedAt(LocalDateTime.now())
            .explanation("MD5 es un algoritmo diseñado para ser RÁPIDO. "
                + "Una GPU moderna puede calcular 10 BILLONES de hashes MD5 por segundo. "
                + "Sin sal, el mismo password siempre produce el mismo hash, "
                + "permitiendo tablas de búsqueda inversa pre-calculadas.")
            .realWorldImpact("Acceso no autorizado a las cuentas de todos los usuarios "
                + "cuyas contraseñas aparezcan en la rainbow table. "
                + "En CrackStation.net, 'password123' se crackea en < 1 segundo.")
            .howToPrevent("BCrypt, Argon2, scrypt. Estos algoritmos son LENTOS por diseño "
                + "y cada hash incluye una sal aleatoria única. "
                + "Mismo password → hashes completamente diferentes.")
            .rainbowTableUsed(buildRainbowTableForDisplay())
            .build();
    }

    /**
     * ATAQUE 3: Credential Stuffing via Password Reuse
     *
     * Demuestra que sin sal, todos los usuarios que usan "password123"
     * pueden ser identificados y atacados en bloque.
     */
    @Transactional(readOnly = true)
    public AttackResult simulateCredentialStuffing() {
        log.warn("[HACKER-SIM] Ejecutando: Credential Stuffing Attack");

        // Contraseña frecuente que se intenta
        String targetPassword = "password123";
        String targetHash = cryptoPort.hashMd5Insecure(targetPassword);

        List<InsecureUserEntity> vulnerableUsers =
            insecureRepo.findUsersWithSamePassword(targetHash);

        List<Map<String, String>> exposed = vulnerableUsers.stream().map(u -> {
            Map<String, String> row = new LinkedHashMap<>();
            row.put("email", u.getEmail());
            row.put("password", targetPassword + " ← (misma contraseña para todos)");
            row.put("pan", u.getPan());
            return row;
        }).collect(Collectors.toList());

        return AttackResult.builder()
            .attackId("ATK-003")
            .attackName("Credential Stuffing — Contraseñas reutilizadas")
            .technique("SELECT email FROM insecure_users WHERE password_hash = '" + targetHash + "';")
            .severity("ALTO")
            .successful(!exposed.isEmpty())
            .dataExposed(exposed)
            .recordsCompromised(exposed.size())
            .executedAt(LocalDateTime.now())
            .explanation("Sin sal en el hash, todos los usuarios que usaron '" + targetPassword
                + "' tienen EXACTAMENTE el mismo hash en la BD: " + targetHash
                + ". Una sola búsqueda SQL revela todos sus emails.")
            .realWorldImpact("El atacante obtiene una lista de emails que comparten "
                + "la misma contraseña. Puede iniciar sesión en todos esos servicios "
                + "si la contraseña se reutilizó en otros sitios.")
            .howToPrevent("BCrypt incorpora una sal de 22 caracteres aleatoria por usuario. "
                + "Mismo password, usuario diferente → hash completamente diferente. "
                + "Imposible correlacionar usuarios por contraseña.")
            .build();
    }

    /**
     * ATAQUE 4: Unauthorized Data Access — Sin autenticación
     *
     * Simula acceso a la API insegura sin ningún token.
     */
    @Transactional(readOnly = true)
    public AttackResult simulateUnauthorizedAccess() {
        log.warn("[HACKER-SIM] Ejecutando: Unauthorized Access Attack");

        List<InsecureUserEntity> users = insecureRepo.findAll();

        List<Map<String, String>> exposed = users.stream().map(u -> {
            Map<String, String> row = new LinkedHashMap<>();
            row.put("name", u.getName());
            row.put("email", u.getEmail());
            row.put("pan", u.getPan());
            row.put("phone", u.getPhone());
            return row;
        }).collect(Collectors.toList());

        return AttackResult.builder()
            .attackId("ATK-004")
            .attackName("Acceso no autorizado — Endpoint sin protección")
            .technique("curl -s http://localhost:8080/api/insecure/users")
            .severity("ALTO")
            .successful(true)
            .dataExposed(exposed)
            .recordsCompromised(users.size())
            .executedAt(LocalDateTime.now())
            .explanation("El endpoint /api/insecure/users no requiere autenticación. "
                + "Cualquier persona con acceso de red puede hacer una petición HTTP "
                + "y obtener todos los datos de todos los usuarios.")
            .realWorldImpact("Enumeración masiva de usuarios, scraping de datos, "
                + "harvesting de emails para phishing, robo de PANs.")
            .howToPrevent("Requerir JWT Bearer token. Aplicar @PreAuthorize en los endpoints. "
                + "Implementar rate limiting. Registrar todos los accesos (audit log).")
            .build();
    }

    /**
     * ATAQUE 5: Log File Exfiltration
     *
     * El servicio inseguro loguea el PAN en texto plano.
     * Simula lo que un atacante encuentra en los logs.
     */
    @Transactional(readOnly = true)
    public AttackResult simulateLogExfiltration() {
        log.warn("[HACKER-SIM] Ejecutando: Log Exfiltration Attack");

        // Simula las entradas de log que generaría el servicio inseguro
        List<Map<String, String>> logEntries = insecureRepo.findAll().stream().map(u -> {
            Map<String, String> entry = new LinkedHashMap<>();
            // Este es el formato del log que genera InsecureUserService.register()
            entry.put("log_line", String.format(
                "WARN [InsecureUserService] Registrando usuario: email=%s, pan=%s",
                u.getEmail(), u.getPan()  // ← PAN en el log
            ));
            entry.put("timestamp", u.getCreatedAt() != null
                ? u.getCreatedAt().toString() : "2024-01-15T10:30:00");
            return entry;
        }).collect(Collectors.toList());

        return AttackResult.builder()
            .attackId("ATK-005")
            .attackName("Log Exfiltration — Datos sensibles en archivos de log")
            .technique("tail -f application.log | grep 'pan='")
            .severity("MEDIO")
            .successful(true)
            .dataExposed(logEntries)
            .recordsCompromised(logEntries.size())
            .executedAt(LocalDateTime.now())
            .explanation("El servicio inseguro usa log.warn() incluyendo el PAN completo. "
                + "Los archivos de log se almacenan en disco sin cifrar, "
                + "se rotan a sistemas centralizados (ELK, Splunk) "
                + "y son accesibles por DevOps/SRE sin necesidad de acceso a BD.")
            .realWorldImpact("Cualquier persona con acceso al servidor de logs "
                + "puede extraer PANs y datos personales sin tocar la base de datos.")
            .howToPrevent("Nunca loguear datos sensibles. "
                + "Usar masking en todos los logs: log.info('pan={}', maskPan(pan)). "
                + "Implementar MDC (Mapped Diagnostic Context) con datos anonimizados.")
            .build();
    }

    // ─── Mini Rainbow Table Educativa ────────────────────────────────────────

    private Map<String, String> buildEducationalRainbowTable() {
        Map<String, String> table = new HashMap<>();
        // Pre-calculamos los MD5 de contraseñas comunes
        String[] commonPasswords = {
            "password123", "admin2024", "123456", "qwerty",
            "letmein", "welcome", "monkey", "dragon",
            "master", "sunshine", "password", "1234567890"
        };
        for (String pwd : commonPasswords) {
            table.put(cryptoPort.hashMd5Insecure(pwd), pwd);
        }
        return table;
    }

    private List<Map<String, String>> buildRainbowTableForDisplay() {
        String[] samples = {"password123", "admin2024", "123456", "qwerty"};
        List<Map<String, String>> display = new ArrayList<>();
        for (String pwd : samples) {
            Map<String, String> row = new LinkedHashMap<>();
            row.put("password", pwd);
            row.put("md5_hash", cryptoPort.hashMd5Insecure(pwd));
            display.add(row);
        }
        return display;
    }

    // ─── DTO del resultado de ataque ─────────────────────────────────────────

    @lombok.Data
    @lombok.Builder
    @lombok.NoArgsConstructor
    @lombok.AllArgsConstructor
    public static class AttackResult {
        private String attackId;
        private String attackName;
        private String technique;
        private String severity;
        private boolean successful;
        private List<Map<String, String>> dataExposed;
        private int recordsCompromised;
        private LocalDateTime executedAt;
        private String explanation;
        private String realWorldImpact;
        private String howToPrevent;
        private List<Map<String, String>> rainbowTableUsed; // solo ATK-002
    }
}
