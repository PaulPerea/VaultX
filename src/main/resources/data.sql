-- ============================================================
-- DataShield Lab — Seed de datos educativos
-- ============================================================
-- ESCENARIO INSEGURO: datos en texto plano, hash MD5
-- MD5 de "password123" = 482c811da5d5b4bc6d497ffa98491e38
-- MD5 de "admin2024"   = 3cf3b350a74a1e0e28e0e3af0e16e57e
-- ============================================================
INSERT INTO insecure_users (id, name, email, password_hash, pan, phone, created_at)
VALUES
  (1, 'Carlos Mendoza',  'carlos.mendoza@example.com',  '482c811da5d5b4bc6d497ffa98491e38', '4532015112830366', '987654321', NOW()),
  (2, 'Ana Torres',      'ana.torres@example.com',      '3cf3b350a74a1e0e28e0e3af0e16e57e', '5425233430109903', '912345678', NOW()),
  (3, 'Pedro Quispe',    'pedro.quispe@example.com',    '482c811da5d5b4bc6d497ffa98491e38', '4916338506082832', '945678123', NOW());

-- ============================================================
-- ESCENARIO SEGURO: BCrypt + AES-256-GCM
-- BCrypt de "password123" con cost=12
-- PAN cifrado con AES-GCM (se genera en runtime, este es un placeholder)
-- Los datos reales se insertan vía DataInitializer.java
-- ============================================================
