package com.datashield.infrastructure.persistence.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * Entidad JPA que mapea la tabla SECURE_USERS.
 *
 * PROTECCIONES APLICADAS:
 * - password_bcrypt: BCrypt con sal automática y cost=12
 * - pan_encrypted: AES-256-GCM en Base64
 * - pan_iv: IV aleatorio por registro (requerido para descifrar)
 * - email: en texto para autenticación, pero ofuscado en la API
 *
 * Si un atacante obtiene esta tabla, solo verá
 * ciphertext y hashes irreversibles.
 */
@Entity
@Table(name = "secure_users")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SecureUserEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String name;

    /** Email en texto — necesario para autenticación.
     *  En una implementación más avanzada se cifraría también. */
    @Column(nullable = false, unique = true)
    private String email;

    /**
     * Contraseña con BCrypt.
     * Formato: $2a$12$<22-char-salt><31-char-hash>
     * La sal está embebida en el hash — no necesita columna separada.
     */
    @Column(name = "password_bcrypt", nullable = false)
    private String passwordBcrypt;

    /**
     * PAN cifrado con AES-256-GCM.
     * Almacenado en Base64. Sin el IV y la clave, es inútil.
     */
    @Column(name = "pan_encrypted", nullable = false)
    private String panEncrypted;

    /**
     * IV (Initialization Vector) para AES-GCM.
     * Un IV diferente por cada registro hace que el mismo PAN
     * produzca un ciphertext diferente.
     */
    @Column(name = "pan_iv", nullable = false)
    private String panIv;

    /** Teléfono ofuscado — el original no se almacena */
    @Column(name = "phone_masked")
    private String phoneMasked;

    @Column(name = "created_at")
    private LocalDateTime createdAt;

    @PrePersist
    protected void onCreate() {
        if (createdAt == null) createdAt = LocalDateTime.now();
    }
}
