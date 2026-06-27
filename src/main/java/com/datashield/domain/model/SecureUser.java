package com.datashield.domain.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * Modelo de dominio para el escenario SEGURO.
 *
 * BUENAS PRÁCTICAS aplicadas:
 * - Password con BCrypt (cost=12) + sal automática
 * - PAN cifrado con AES-256-GCM + IV aleatorio por registro
 * - Email ofuscado al exponerse via API
 * - Separación entre datos en reposo (cifrados) y datos en tránsito (ofuscados)
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SecureUser {

    private Long id;

    /** Nombre completo — candidato a ofuscación parcial en la respuesta */
    private String name;

    /**
     * Email almacenado en texto para poder autenticar,
     * pero ofuscado al exponerse: c***@example.com
     */
    private String email;

    /**
     * Contraseña hasheada con BCrypt (cost=12).
     * VENTAJAS:
     * - Incorpora sal automática (diferente por usuario)
     * - Adaptable: se puede aumentar el cost factor con el tiempo
     * - Resistente a rainbow tables y GPUs de fuerza bruta
     */
    private String passwordBcrypt;  // ej: $2a$12$...

    /**
     * PAN cifrado con AES-256-GCM.
     * Se almacena en Base64 junto con el IV.
     * NUNCA se expone en la respuesta — solo el PAN ofuscado.
     */
    private String panEncrypted;

    /**
     * IV (Initialization Vector) aleatorio usado para cifrar el PAN.
     * Almacenado junto al ciphertext para poder descifrar cuando sea necesario.
     * Diferente por cada registro → mismo PAN = diferente ciphertext.
     */
    private String panIv;

    /** Teléfono ofuscado: 9**6**321 */
    private String phoneMasked;

    private LocalDateTime createdAt;

    /**
     * Calcula el nivel de riesgo del registro (0-100).
     */
    public int getRiskScore() {
        return 8; // Riesgo mínimo: protecciones en capas aplicadas
    }
}
