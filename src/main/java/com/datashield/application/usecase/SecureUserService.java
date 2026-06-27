package com.datashield.application.usecase;

import com.datashield.domain.model.SecureUser;
import com.datashield.domain.port.CryptoPort;
import com.datashield.domain.port.MaskingPort;
import com.datashield.infrastructure.persistence.entity.SecureUserEntity;
import com.datashield.infrastructure.persistence.repository.SecureUserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

/**
 * Caso de uso para el ESCENARIO SEGURO.
 *
 * Implementa buenas prácticas en capas:
 * 1. BCrypt para contraseñas
 * 2. AES-256-GCM para datos sensibles en reposo
 * 3. Masking en la capa de respuesta
 * 4. Logging seguro (sin datos sensibles)
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class SecureUserService {

    private final SecureUserRepository repository;
    private final CryptoPort cryptoPort;
    private final MaskingPort maskingPort;

    /**
     * Registra un usuario aplicando todas las capas de protección.
     */
    @Transactional
    public SecureUser register(String name, String email, String password, String pan, String phone) {
        // Log seguro — nunca se loguea el PAN o password
        log.info("[SECURE] Registrando usuario: email={}", maskingPort.maskEmail(email));

        // 1. Hash BCrypt con sal automática
        String bcryptHash = cryptoPort.hashBcrypt(password);

        // 2. Cifrar PAN con AES-256-GCM
        String[] encrypted = cryptoPort.encryptAesGcm(pan);
        String panEncrypted = encrypted[0];
        String panIv = encrypted[1];

        // 3. El teléfono se ofusca antes de persistir (el original no se guarda)
        String phoneMasked = maskingPort.maskPhone(phone);

        SecureUserEntity entity = SecureUserEntity.builder()
            .name(name)
            .email(email)
            .passwordBcrypt(bcryptHash)
            .panEncrypted(panEncrypted)
            .panIv(panIv)
            .phoneMasked(phoneMasked)
            .build();

        SecureUserEntity saved = repository.save(entity);

        log.info("[SECURE] Usuario registrado con ID: {}", saved.getId());
        return toModel(saved);
    }

    /**
     * Lista todos los usuarios con datos ofuscados.
     * Requiere autenticación (controlado por Spring Security en el controller).
     */
    @Transactional(readOnly = true)
    public List<SecureUser> findAll() {
        return repository.findAll()
            .stream()
            .map(this::toModel)
            .collect(Collectors.toList());
    }

    /**
     * Descifra el PAN de un usuario específico.
     * Operación restringida — solo ADMIN puede invocarla.
     * En producción esto se auditaría y requeriría 2FA.
     */
    @Transactional(readOnly = true)
    public String decryptPanForAudit(Long userId) {
        log.warn("[AUDIT] Descifrado de PAN solicitado para userId={}", userId);
        return repository.findById(userId)
            .map(u -> cryptoPort.decryptAesGcm(u.getPanEncrypted(), u.getPanIv()))
            .orElseThrow(() -> new RuntimeException("Usuario no encontrado: " + userId));
    }

    /**
     * Autenticación segura con BCrypt.
     * BCrypt.checkpw maneja la comparación en tiempo constante.
     */
    @Transactional(readOnly = true)
    public boolean authenticate(String email, String password) {
        return repository.findByEmail(email)
            .map(u -> cryptoPort.verifyBcrypt(password, u.getPasswordBcrypt()))
            .orElse(false);
    }

    /** Convierte entidad a modelo de dominio aplicando ofuscación */
    private SecureUser toModel(SecureUserEntity e) {
        return SecureUser.builder()
            .id(e.getId())
            .name(maskingPort.maskName(e.getName()))         // "Carlos M."
            .email(maskingPort.maskEmail(e.getEmail()))      // "c***@example.com"
            .passwordBcrypt("[PROTEGIDO]")                   // nunca se expone el hash
            .panEncrypted(maskingPort.maskPan(              // "**** **** **** 0366"
                // Descifra solo para generar la versión ofuscada
                // En producción se almacenaría el PAN ofuscado separado
                "[cifrado-aes-gcm]"))
            .panIv("[PROTEGIDO]")
            .phoneMasked(e.getPhoneMasked())
            .createdAt(e.getCreatedAt())
            .build();
    }
}
