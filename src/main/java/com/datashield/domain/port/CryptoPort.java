package com.datashield.domain.port;

/**
 * Puerto (interfaz) de dominio para operaciones criptográficas.
 * El dominio define el contrato; la infraestructura lo implementa.
 */
public interface CryptoPort {

    /**
     * Cifra un texto con AES-256-GCM.
     * @return array con [ciphertext_base64, iv_base64]
     */
    String[] encryptAesGcm(String plainText);

    /**
     * Descifra un texto cifrado con AES-256-GCM.
     * @param cipherText ciphertext en Base64
     * @param iv IV en Base64
     */
    String decryptAesGcm(String cipherText, String iv);

    /**
     * Genera hash BCrypt con cost=12.
     * Incluye sal automática.
     */
    String hashBcrypt(String rawPassword);

    /**
     * Verifica si un password coincide con su hash BCrypt.
     */
    boolean verifyBcrypt(String rawPassword, String hash);

    /**
     * Genera hash MD5 (INSEGURO — solo para demostrar el escenario vulnerable).
     * @deprecated Solo uso educativo. Nunca en producción.
     */
    @Deprecated(since = "educational-only")
    String hashMd5Insecure(String input);

    /**
     * Genera un IV aleatorio seguro para AES-GCM.
     */
    byte[] generateSecureIv();
}
