package com.datashield.infrastructure.crypto;

import com.datashield.domain.port.CryptoPort;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

/**
 * Adaptador de infraestructura que implementa las operaciones criptográficas.
 *
 * Algoritmos utilizados:
 * - AES-256-GCM: cifrado autenticado (confidencialidad + integridad)
 * - BCrypt (cost=12): hashing de contraseñas resistente a fuerza bruta
 * - MD5: SOLO para demostración del escenario inseguro
 */
@Component
public class CryptoAdapter implements CryptoPort {

    private static final String AES_ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH = 128; // bits
    private static final int GCM_IV_LENGTH = 12;   // bytes — recomendado por NIST
    private static final int BCRYPT_COST = 12;

    private final SecretKey aesKey;
    private final SecureRandom secureRandom = new SecureRandom();

    public CryptoAdapter(@Value("${datashield.crypto.aes-secret-key}") String rawKey) {
        // Deriva una clave AES de 256 bits desde el string de configuración
        byte[] keyBytes = Arrays.copyOf(
            rawKey.getBytes(StandardCharsets.UTF_8), 32 // 32 bytes = 256 bits
        );
        this.aesKey = new SecretKeySpec(keyBytes, "AES");
    }

    // ─── AES-256-GCM ────────────────────────────────────────────────────────

    @Override
    public String[] encryptAesGcm(String plainText) {
        try {
            byte[] iv = generateSecureIv();
            GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);

            Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, aesKey, parameterSpec);

            byte[] cipherText = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

            return new String[]{
                Base64.getEncoder().encodeToString(cipherText),
                Base64.getEncoder().encodeToString(iv)
            };
        } catch (Exception e) {
            throw new CryptoException("Error al cifrar con AES-GCM", e);
        }
    }

    @Override
    public String decryptAesGcm(String cipherTextB64, String ivB64) {
        try {
            byte[] iv = Base64.getDecoder().decode(ivB64);
            byte[] cipherText = Base64.getDecoder().decode(cipherTextB64);

            GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);

            Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, aesKey, parameterSpec);

            byte[] plainText = cipher.doFinal(cipherText);
            return new String(plainText, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new CryptoException("Error al descifrar con AES-GCM", e);
        }
    }

    @Override
    public byte[] generateSecureIv() {
        byte[] iv = new byte[GCM_IV_LENGTH];
        secureRandom.nextBytes(iv);
        return iv;
    }

    // ─── BCrypt ─────────────────────────────────────────────────────────────

    @Override
    public String hashBcrypt(String rawPassword) {
        // BCrypt genera la sal automáticamente y la incorpora al hash resultante
        return BCrypt.hashpw(rawPassword, BCrypt.gensalt(BCRYPT_COST));
    }

    @Override
    public boolean verifyBcrypt(String rawPassword, String hash) {
        return BCrypt.checkpw(rawPassword, hash);
    }

    // ─── MD5 (INSEGURO — Solo Demo Educativo) ───────────────────────────────

    @Override
    @Deprecated
    public String hashMd5Insecure(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] digest = md.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            throw new CryptoException("Error al generar MD5", e);
        }
    }

    // ─── Excepción interna ──────────────────────────────────────────────────

    public static class CryptoException extends RuntimeException {
        public CryptoException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
