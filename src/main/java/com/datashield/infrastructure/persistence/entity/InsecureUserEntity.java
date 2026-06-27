package com.datashield.infrastructure.persistence.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * Entidad JPA que mapea la tabla INSECURE_USERS.
 *
 * VULNERABILIDADES INTENCIONADAS (educativo):
 * - password_hash: columna con MD5 sin sal
 * - pan: número de tarjeta en TEXTO PLANO
 * - email: sin cifrar, directo en BD
 *
 * En una auditoría real, cualquier DBA o atacante con acceso
 * a la BD vería todos estos datos directamente.
 */
@Entity
@Table(name = "insecure_users")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class InsecureUserEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String name;

    @Column(nullable = false, unique = true)
    private String email;

    /**
     * Contraseña hasheada con MD5 — SIN SAL.
     * Columna intencionalmente vulnerable para la demo.
     */
    @Column(name = "password_hash", nullable = false)
    private String passwordHash;

    /**
     * PAN en texto plano — DATO SENSIBLE EXPUESTO.
     * Violación directa de PCI-DSS Requisito 3.
     */
    @Column(name = "pan", nullable = false)
    private String pan;

    @Column(name = "phone")
    private String phone;

    @Column(name = "created_at")
    private LocalDateTime createdAt;

    @PrePersist
    protected void onCreate() {
        if (createdAt == null) createdAt = LocalDateTime.now();
    }
}
