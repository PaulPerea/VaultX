package com.datashield.domain.port;

/**
 * Puerto para ofuscación de datos personales (PII masking).
 * Implementa técnicas de Data Masking para reducir exposición en API responses.
 */
public interface MaskingPort {

    /**
     * Ofusca un PAN mostrando solo los últimos 4 dígitos.
     * Ej: "4532015112830366" → "**** **** **** 0366"
     */
    String maskPan(String pan);

    /**
     * Ofusca un email mostrando solo el primer carácter y el dominio.
     * Ej: "carlos.mendoza@example.com" → "c***@example.com"
     */
    String maskEmail(String email);

    /**
     * Ofusca un teléfono mostrando solo los últimos 3 dígitos.
     * Ej: "987654321" → "9****321"
     */
    String maskPhone(String phone);

    /**
     * Ofusca un nombre mostrando solo las iniciales del apellido.
     * Ej: "Carlos Mendoza" → "Carlos M."
     */
    String maskName(String fullName);
}
