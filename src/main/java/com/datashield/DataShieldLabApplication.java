package com.datashield;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * ╔══════════════════════════════════════════════════════════╗
 * ║           DataShield Lab — Proyecto Educativo            ║
 * ║     Protección de Datos & Simulación de Ataques          ║
 * ╠══════════════════════════════════════════════════════════╣
 * ║  Swagger UI → http://localhost:8080/swagger-ui.html      ║
 * ║  H2 Console → http://localhost:8080/h2-console           ║
 * ║  Risk Report → http://localhost:8080/api/compare/risk... ║
 * ╚══════════════════════════════════════════════════════════╝
 */
@SpringBootApplication
public class DataShieldLabApplication {

    public static void main(String[] args) {
        SpringApplication.run(DataShieldLabApplication.class, args);
    }
}
