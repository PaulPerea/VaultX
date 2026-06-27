package com.datashield.application.usecase;

import com.datashield.domain.model.InsecureUser;
import com.datashield.domain.port.CryptoPort;
import com.datashield.infrastructure.persistence.entity.InsecureUserEntity;
import com.datashield.infrastructure.persistence.repository.InsecureUserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

/**
 * Caso de uso para el ESCENARIO INSEGURO.
 *
 * Este servicio implementa deliberadamente malas prácticas de seguridad
 * con fines educativos. Cada método documenta qué está mal y por qué.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class InsecureUserService {

    private final InsecureUserRepository repository;
    private final CryptoPort cryptoPort;

    /**
     * Registra un usuario con prácticas inseguras.
     *
     * PROBLEMAS:
     * 1. MD5 sin sal → reversible con rainbow tables
     * 2. PAN en texto plano → visible en BD y logs
     * 3. Log del email completo → información sensible en logs
     */
    @Transactional
    public InsecureUser register(String name, String email, String password, String pan, String phone) {
        log.warn("[INSECURE] Registrando usuario: email={}, pan={}", email, pan); // PROBLEMA: loguea PAN!

        // MAL: MD5 sin sal
        String md5Hash = cryptoPort.hashMd5Insecure(password);

        InsecureUserEntity entity = InsecureUserEntity.builder()
            .name(name)
            .email(email)
            .passwordHash(md5Hash)  // MD5 reversible
            .pan(pan)               // Texto plano
            .phone(phone)
            .build();

        InsecureUserEntity saved = repository.save(entity);
        return toModel(saved);
    }

    /**
     * Lista todos los usuarios — SIN ningún filtro de acceso.
     * Cualquier usuario puede ver todos los datos de todos.
     */
    @Transactional(readOnly = true)
    public List<InsecureUser> findAll() {
        return repository.findAll()
            .stream()
            .map(this::toModel)
            .collect(Collectors.toList());
    }

    /**
     * Busca usuarios con la MISMA contraseña.
     * Posible porque MD5 sin sal siempre produce el mismo hash.
     * Un atacante con acceso a la BD puede identificar grupos de usuarios
     * con contraseñas idénticas y atacarlos todos a la vez.
     */
    @Transactional(readOnly = true)
    public List<InsecureUser> findUsersWithSamePassword(String passwordToSearch) {
        String hash = cryptoPort.hashMd5Insecure(passwordToSearch);
        log.warn("[HACKER-SIM] Buscando usuarios con hash MD5: {}", hash);
        return repository.findUsersWithSamePassword(hash)
            .stream()
            .map(this::toModel)
            .collect(Collectors.toList());
    }

    /**
     * Autenticación insegura — compara MD5 directamente.
     */
    @Transactional(readOnly = true)
    public boolean authenticate(String email, String password) {
        String hash = cryptoPort.hashMd5Insecure(password);
        return repository.findByEmail(email)
            .map(u -> u.getPasswordHash().equals(hash))
            .orElse(false);
    }

    private InsecureUser toModel(InsecureUserEntity e) {
        return InsecureUser.builder()
            .id(e.getId())
            .name(e.getName())
            .email(e.getEmail())
            .passwordHash(e.getPasswordHash())
            .pan(e.getPan())           // Retorna el PAN completo — EXPOSICIÓN
            .phone(e.getPhone())
            .createdAt(e.getCreatedAt())
            .build();
    }
}
