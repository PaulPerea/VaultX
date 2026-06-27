# 🔐 DataShield Lab

> **Proyecto académico** de demostración de protección de datos con simulación controlada de ataques.  
> Java 17 · Spring Boot 3.2 · AES-256-GCM · BCrypt · JWT · H2

---

## 🚀 Arrancar el proyecto

```bash
# Clonar / descomprimir el proyecto
cd datashield-lab

# Compilar y arrancar
./mvnw spring-boot:run

# La app arranca en http://localhost:8080
```

---

## 🗺️ URLs de la demo

| URL | Descripción |
|-----|-------------|
| http://localhost:8080/swagger-ui.html | **Swagger UI — punto de entrada principal** |
| http://localhost:8080/h2-console | **H2 Console — ver la BD directamente** |
| http://localhost:8080/api/compare/risk-report | Reporte comparativo de riesgo |
| http://localhost:8080/api/hacker-sim/attacks/all | Todos los ataques simulados |

**H2 Console config:**
- JDBC URL: `jdbc:h2:mem:datashielddb`
- User: `sa` / Password: *(vacío)*

---

## 🎯 Flujo de la presentación académica

### Paso 1 — Ver los datos inseguros (sin autenticación)
```
GET /api/insecure/users
```
Respuesta: PAN en texto plano, MD5 visible. No se necesita token.

### Paso 2 — Simular el ataque del hacker
```
GET /api/hacker-sim/attacks/all
```
Ejecuta 5 ataques y muestra qué datos obtendría un atacante.

### Paso 3 — Ver el reporte comparativo
```
GET /api/compare/risk-report
```
Compara ambos escenarios: riesgo 95/100 vs 8/100.

### Paso 4 — Obtener JWT y acceder al escenario seguro
```
POST /api/auth/login
{ "email": "user@datashield.com", "password": "user123" }
```
Copiar el token → usar en Swagger UI con el candado 🔒.

### Paso 5 — Ver los datos protegidos
```
GET /api/secure/users   (con Bearer token)
```
Respuesta: email ofuscado, password protegido, PAN enmascarado.

### Paso 6 — Ver la BD directamente en H2 Console
```sql
-- Escenario INSEGURO: datos visibles
SELECT * FROM insecure_users;

-- Escenario SEGURO: solo ciphertext
SELECT * FROM secure_users;
```

---

## 🧪 Ejecutar los tests educativos

```bash
./mvnw test
```

Los tests imprimen en consola la comparación entre escenarios:
```
[INSEGURO] MD5('password123') = 482c811da5d5b4bc6d497ffa98491e38
[SEGURO]   BCrypt(1): $2a$12$abc...
[SEGURO]   BCrypt(2): $2a$12$xyz...  ← DIFERENTE por la sal
[ATAQUE-002] Email: carlos.mendoza@example.com | Password CRACKEADA: password123
[REPORTE] Reducción de riesgo: 87 puntos
```

---

## 💀 Ataques simulados

| ID | Nombre | Severidad | Técnica |
|----|--------|-----------|---------|
| ATK-001 | Database Dump | CRÍTICO | SELECT * sin cifrado |
| ATK-002 | Rainbow Table MD5 | CRÍTICO | Crackeo de hashes |
| ATK-003 | Credential Stuffing | ALTO | Contraseñas reutilizadas |
| ATK-004 | Acceso no autorizado | ALTO | API sin auth |
| ATK-005 | Log Exfiltration | MEDIO | PANs en archivos de log |

---

## 🔒 Protecciones implementadas

| Técnica | Implementación | Clase |
|---------|---------------|-------|
| Hashing seguro | BCrypt cost=12 | `CryptoAdapter` |
| Cifrado en reposo | AES-256-GCM + IV random | `CryptoAdapter` |
| Ofuscación API | Data Masking | `DataMaskAdapter` |
| Control de acceso | JWT + Spring Security | `SecurityConfig` |
| Roles RBAC | USER / ADMIN | `@PreAuthorize` |

---

## 📁 Estructura del proyecto

```
datashield-lab/
├── src/main/java/com/datashield/
│   ├── DataShieldLabApplication.java     ← Main
│   ├── domain/
│   │   ├── model/                        ← InsecureUser, SecureUser, RiskReport
│   │   └── port/                         ← CryptoPort, MaskingPort (interfaces)
│   ├── application/usecase/              ← Servicios de negocio + HackerSimulation
│   ├── infrastructure/
│   │   ├── crypto/CryptoAdapter.java     ← AES-GCM + BCrypt + MD5
│   │   ├── masking/DataMaskAdapter.java  ← Ofuscación PAN/email/phone
│   │   ├── persistence/                  ← Entidades JPA + Repositorios
│   │   └── security/                     ← JWT + Spring Security
│   └── adapter/rest/                     ← Controllers REST
└── src/test/                             ← Tests de integración educativos
```

---

## ⚠️ Aviso educativo

Este proyecto contiene vulnerabilidades **intencionadas** en el escenario inseguro.  
Todo corre en H2 en memoria con datos de prueba.  
**No usar el escenario inseguro como referencia para producción.**
