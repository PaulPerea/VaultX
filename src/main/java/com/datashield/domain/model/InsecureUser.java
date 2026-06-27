package com.datashield.domain.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * Modelo de dominio para el escenario INSEGURO.
 *
 * VULNERABILIDADES INTENCIONADAS (solo fines educativos):
 * - password almacenada como MD5 (reversible, sin sal)
 * - PAN (número de tarjeta) en texto plano
 * - email sin ofuscación
 * - teléfono sin protección
 *
 * NUNCA replicar este patrón en producción.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class InsecureUser {

    private Long id;

    /** Nombre completo sin ningún tipo de ofuscación */
    private String name;

    /** Email en texto plano — filtrable con SQL directo */
    private String email;

    /**
     * Contraseña hasheada con MD5.
     * PROBLEMA: MD5 es rápido → vulnerable a rainbow tables y fuerza bruta.
     * Sin sal → dos usuarios con la misma contraseña tienen el mismo hash.
     */
    private String passwordHash;  // MD5, ej: 482c811da5d5b4bc6d497ffa98491e38

    /**
     * PAN (Primary Account Number) — número de tarjeta en texto plano.
     * PROBLEMA CRÍTICO: visible directamente en la base de datos,
     * en logs, y en cualquier backup sin cifrar.
     */
    private String pan;  // ej: "4532015112830366"

    /** Teléfono sin protección */
    private String phone;

    private LocalDateTime createdAt;

    /**
     * Calcula el nivel de riesgo del registro (0-100).
     * Usado en el reporte comparativo educativo.
     */
    public int getRiskScore() {
        return 95; // Casi máximo: múltiples vulnerabilidades críticas
    }
}
