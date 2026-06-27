package com.datashield.adapter.rest.controller;

import com.datashield.application.usecase.RiskReportService;
import com.datashield.domain.model.RiskReport;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/compare")
@RequiredArgsConstructor
@Tag(name = "📊 Reporte Comparativo",
     description = "Análisis de riesgo lado a lado entre ambos escenarios")
public class CompareController {

    private final RiskReportService reportService;

    @GetMapping("/risk-report")
    @Operation(
        summary = "Reporte comparativo de riesgo",
        description = """
            Genera un reporte completo comparando:
            - Cómo se ven los datos en el escenario inseguro vs protegido
            - Puntuación de riesgo (0-100) para cada escenario
            - Lista de vulnerabilidades con referencia CWE
            - Mitigaciones recomendadas
            
            Este es el endpoint principal para la presentación académica.
            """
    )
    public ResponseEntity<RiskReport> riskReport() {
        return ResponseEntity.ok(reportService.generateReport());
    }
}
