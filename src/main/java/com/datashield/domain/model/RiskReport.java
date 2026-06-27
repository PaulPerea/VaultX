package com.datashield.domain.model;

import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.List;

/**
 * Reporte educativo que compara ambos escenarios lado a lado.
 * Este es el corazón pedagógico del proyecto.
 */
@Data
@Builder
public class RiskReport {

    private LocalDateTime generatedAt;

    /** Datos del escenario inseguro (lo que vería un atacante) */
    private ScenarioSnapshot insecureScenario;

    /** Datos del escenario protegido */
    private ScenarioSnapshot secureScenario;

    /** Lista de vulnerabilidades detectadas en el escenario inseguro */
    private List<Vulnerability> vulnerabilitiesFound;

    /** Diferencia de riesgo entre ambos escenarios */
    private int riskReduction;

    @Data
    @Builder
    public static class ScenarioSnapshot {
        private String scenarioName;
        private int riskScore;           // 0-100
        private String riskLevel;        // CRÍTICO / ALTO / MEDIO / BAJO
        private String passwordStored;   // cómo se ve la contraseña en BD
        private String panStored;        // cómo se ve el PAN en BD
        private String emailExposed;     // cómo se expone el email en API
        private String phoneExposed;     // cómo se expone el teléfono en API
        private List<String> protections;
        private List<String> weaknesses;
    }

    @Data
    @Builder
    public static class Vulnerability {
        private String id;           // CVE o código educativo, ej: EDU-001
        private String name;
        private String severity;     // CRITICAL / HIGH / MEDIUM / LOW
        private String description;
        private String attackVector; // cómo un atacante lo explotaría
        private String mitigation;   // cómo se corrige
        private String cweReference; // ej: CWE-327
    }
}
