package com.datashield.infrastructure;

import com.datashield.application.usecase.SecureUserService;
import com.datashield.infrastructure.persistence.repository.SecureUserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

/**
 * Inicializador que crea los usuarios seguros con cifrado real en runtime.
 * Los usuarios inseguros se crean via data.sql con valores hardcodeados.
 * Los usuarios seguros necesitan el CryptoAdapter para cifrar, por eso se hacen aquí.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class DataInitializer implements ApplicationRunner {

    private final SecureUserService secureUserService;
    private final SecureUserRepository secureUserRepository;

    @Override
    public void run(ApplicationArguments args) {
        if (secureUserRepository.count() > 0) return; // evita duplicados

        log.info("[INIT] Creando usuarios seguros con BCrypt + AES-256-GCM...");

        secureUserService.register(
            "Carlos Mendoza", "carlos.mendoza@example.com",
            "password123", "4532015112830366", "987654321"
        );
        secureUserService.register(
            "Ana Torres", "ana.torres@example.com",
            "admin2024", "5425233430109903", "912345678"
        );
        secureUserService.register(
            "Pedro Quispe", "pedro.quispe@example.com",
            "password123", "4916338506082832", "945678123"
        );

        log.info("[INIT] ✓ {} usuarios seguros creados", secureUserRepository.count());
        log.info("[INIT] ✓ Datos inseguros cargados vía data.sql");
        log.info("[INIT] ────────────────────────────────────────────");
        log.info("[INIT] Swagger UI: http://localhost:8080/swagger-ui.html");
        log.info("[INIT] H2 Console: http://localhost:8080/h2-console");
        log.info("[INIT]   JDBC URL: jdbc:h2:mem:datashielddb");
        log.info("[INIT] ────────────────────────────────────────────");
    }
}
