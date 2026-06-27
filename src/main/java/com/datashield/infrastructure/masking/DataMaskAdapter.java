package com.datashield.infrastructure.masking;

import com.datashield.domain.port.MaskingPort;
import org.springframework.stereotype.Component;

/**
 * Adaptador de ofuscación de datos personales.
 *
 * Técnica utilizada: Static Data Masking (SDM)
 * Los datos originales se preservan en BD; solo se ofuscan al exponerlos.
 */
@Component
public class DataMaskAdapter implements MaskingPort {

    @Override
    public String maskPan(String pan) {
        if (pan == null || pan.length() < 4) return "****";
        // Muestra solo los últimos 4 dígitos — estándar PCI-DSS
        String last4 = pan.substring(pan.length() - 4);
        return "**** **** **** " + last4;
    }

    @Override
    public String maskEmail(String email) {
        if (email == null || !email.contains("@")) return "***@***.***";
        int atIndex = email.indexOf('@');
        String localPart = email.substring(0, atIndex);
        String domain = email.substring(atIndex); // incluye el @

        if (localPart.length() <= 1) return localPart + "***" + domain;
        // Muestra solo el primer carácter: c***@example.com
        return localPart.charAt(0) + "***" + domain;
    }

    @Override
    public String maskPhone(String phone) {
        if (phone == null || phone.length() < 3) return "***";
        // Muestra primer dígito y últimos 3: 9****321
        String first = phone.substring(0, 1);
        String last3 = phone.substring(phone.length() - 3);
        int maskedCount = phone.length() - 4;
        return first + "*".repeat(Math.max(maskedCount, 1)) + last3;
    }

    @Override
    public String maskName(String fullName) {
        if (fullName == null || fullName.trim().isEmpty()) return "***";
        String[] parts = fullName.trim().split("\\s+");
        if (parts.length == 1) return parts[0].charAt(0) + "***";
        // "Carlos Mendoza" → "Carlos M."
        return parts[0] + " " + parts[1].charAt(0) + ".";
    }
}
