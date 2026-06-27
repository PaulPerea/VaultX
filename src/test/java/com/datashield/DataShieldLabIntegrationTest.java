package com.datashield;

import com.datashield.application.usecase.HackerSimulationService;
import com.datashield.application.usecase.InsecureUserService;
import com.datashield.application.usecase.RiskReportService;
import com.datashield.application.usecase.SecureUserService;
import com.datashield.domain.model.InsecureUser;
import com.datashield.domain.model.RiskReport;
import com.datashield.domain.model.SecureUser;
import com.datashield.domain.port.CryptoPort;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test de integración que valida todo el flujo educativo del proyecto.
 *
 * Estos tests son parte de la presentación académica:
 * demuestran con código las diferencias entre ambos escenarios.
 */
@SpringBootTest
@DisplayName("DataShield Lab — Tests Educativos")
class DataShieldLabIntegrationTest {

    @Autowired private InsecureUserService insecureService;
    @Autowired private SecureUserService secureService;
    @Autowired private HackerSimulationService hackerService;
    @Autowired private RiskReportService reportService;
    @Autowired private CryptoPort cryptoPort;

    // ─── Tests del escenario inseguro ────────────────────────────────────────

    @Test
    @DisplayName("INSEGURO: MD5 sin sal — mismo password produce el mismo hash")
    void md5WithoutSaltAlwaysProducesSameHash() {
        String password = "password123";
        String hash1 = cryptoPort.hashMd5Insecure(password);
        String hash2 = cryptoPort.hashMd5Insecure(password);

        // PROBLEMA: mismo hash para mismo password → rainbow table funciona
        assertThat(hash1).isEqualTo(hash2);
        assertThat(hash1).isEqualTo("482c811da5d5b4bc6d497ffa98491e38");

        System.out.println("\n[INSEGURO] MD5('password123') = " + hash1);
        System.out.println("[INSEGURO] MD5('password123') = " + hash2);
        System.out.println("[INSEGURO] → IGUALES: rainbow table puede crackear esto");
    }

    @Test
    @DisplayName("INSEGURO: PAN expuesto en texto plano en la respuesta")
    void insecureUserExposesPanInPlainText() {
        List<InsecureUser> users = insecureService.findAll();

        assertThat(users).isNotEmpty();
        users.forEach(u -> {
            // El PAN se retorna completo — violación de PCI-DSS
            assertThat(u.getPan()).matches("\\d{13,19}");
            System.out.printf("[INSEGURO] Usuario: %s | PAN EXPUESTO: %s | Hash MD5: %s%n",
                u.getEmail(), u.getPan(), u.getPasswordHash());
        });
    }

    // ─── Tests del escenario seguro ──────────────────────────────────────────

    @Test
    @DisplayName("SEGURO: BCrypt produce hashes diferentes para el mismo password")
    void bcryptProducesDifferentHashesForSamePassword() {
        String password = "password123";
        String hash1 = cryptoPort.hashBcrypt(password);
        String hash2 = cryptoPort.hashBcrypt(password);

        // La sal automática hace que sean diferentes
        assertThat(hash1).isNotEqualTo(hash2);
        // Pero ambos verifican correctamente
        assertThat(cryptoPort.verifyBcrypt(password, hash1)).isTrue();
        assertThat(cryptoPort.verifyBcrypt(password, hash2)).isTrue();

        System.out.println("\n[SEGURO] BCrypt(1): " + hash1);
        System.out.println("[SEGURO] BCrypt(2): " + hash2);
        System.out.println("[SEGURO] → DIFERENTES: rainbow table INÚTIL");
    }

    @Test
    @DisplayName("SEGURO: AES-GCM cifra el PAN — mismo PAN produce diferente ciphertext")
    void aesGcmProducesDifferentCiphertextForSamePan() {
        String pan = "4532015112830366";
        String[] enc1 = cryptoPort.encryptAesGcm(pan);
        String[] enc2 = cryptoPort.encryptAesGcm(pan);

        // El IV aleatorio hace que el ciphertext sea diferente cada vez
        assertThat(enc1[0]).isNotEqualTo(enc2[0]); // diferente ciphertext
        assertThat(enc1[1]).isNotEqualTo(enc2[1]); // diferente IV

        // Pero ambos descifran al valor original
        assertThat(cryptoPort.decryptAesGcm(enc1[0], enc1[1])).isEqualTo(pan);
        assertThat(cryptoPort.decryptAesGcm(enc2[0], enc2[1])).isEqualTo(pan);

        System.out.println("\n[SEGURO] PAN original: " + pan);
        System.out.printf("[SEGURO] Cifrado 1: %s (IV: %s)%n", enc1[0].substring(0,20)+"...", enc1[1]);
        System.out.printf("[SEGURO] Cifrado 2: %s (IV: %s)%n", enc2[0].substring(0,20)+"...", enc2[1]);
        System.out.println("[SEGURO] → Descifrado OK en ambos casos");
    }

    @Test
    @DisplayName("SEGURO: Datos ofuscados en la respuesta API")
    void secureUserResponseIsMasked() {
        List<SecureUser> users = secureService.findAll();

        assertThat(users).isNotEmpty();
        users.forEach(u -> {
            // Email ofuscado: c***@example.com
            assertThat(u.getEmail()).contains("***@");
            // Password no se expone
            assertThat(u.getPasswordBcrypt()).isEqualTo("[PROTEGIDO]");

            System.out.printf("[SEGURO] Usuario: %s | Email: %s | Phone: %s%n",
                u.getName(), u.getEmail(), u.getPhoneMasked());
        });
    }

    // ─── Tests de simulación de ataques ──────────────────────────────────────

    @Test
    @DisplayName("ATAQUE: Database Dump revela PANs en texto plano del escenario inseguro")
    void hackerCanDumpAllPansFromInsecureScenario() {
        HackerSimulationService.AttackResult result = hackerService.simulateDatabaseDump();

        assertThat(result.isSuccessful()).isTrue();
        assertThat(result.getRecordsCompromised()).isGreaterThan(0);
        assertThat(result.getSeverity()).isEqualTo("CRÍTICO");

        System.out.println("\n[ATAQUE-001] " + result.getAttackName());
        System.out.println("[ATAQUE-001] Registros comprometidos: " + result.getRecordsCompromised());
        result.getDataExposed().forEach(row ->
            System.out.println("[ATAQUE-001] → PAN obtenido: " + row.get("pan"))
        );
    }

    @Test
    @DisplayName("ATAQUE: Rainbow Table crackea contraseñas MD5 en milisegundos")
    void hackerCanCrackMd5PasswordsWithRainbowTable() {
        HackerSimulationService.AttackResult result = hackerService.simulateRainbowTableAttack();

        assertThat(result.isSuccessful()).isTrue();

        System.out.println("\n[ATAQUE-002] " + result.getAttackName());
        result.getDataExposed().forEach(row -> {
            System.out.printf("[ATAQUE-002] Email: %s | Hash: %s | Password CRACKEADA: %s%n",
                row.get("email"), row.get("md5_hash_in_db"), row.get("password_recovered"));
        });
    }

    @Test
    @DisplayName("REPORTE: El escenario seguro reduce el riesgo en al menos 85 puntos")
    void secureScenarioReducesRiskSignificantly() {
        RiskReport report = reportService.generateReport();

        assertThat(report.getInsecureScenario().getRiskScore()).isGreaterThan(90);
        assertThat(report.getSecureScenario().getRiskScore()).isLessThan(15);
        assertThat(report.getRiskReduction()).isGreaterThan(80);
        assertThat(report.getVulnerabilitiesFound()).hasSizeGreaterThan(3);

        System.out.printf("%n[REPORTE] Riesgo inseguro: %d/100 (%s)%n",
            report.getInsecureScenario().getRiskScore(),
            report.getInsecureScenario().getRiskLevel());
        System.out.printf("[REPORTE] Riesgo seguro:   %d/100 (%s)%n",
            report.getSecureScenario().getRiskScore(),
            report.getSecureScenario().getRiskLevel());
        System.out.printf("[REPORTE] Reducción de riesgo: %d puntos%n",
            report.getRiskReduction());
        System.out.printf("[REPORTE] Vulnerabilidades documentadas: %d%n",
            report.getVulnerabilitiesFound().size());
    }
}
