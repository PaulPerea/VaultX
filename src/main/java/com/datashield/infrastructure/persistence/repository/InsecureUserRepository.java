package com.datashield.infrastructure.persistence.repository;

import com.datashield.infrastructure.persistence.entity.InsecureUserEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface InsecureUserRepository extends JpaRepository<InsecureUserEntity, Long> {

    Optional<InsecureUserEntity> findByEmail(String email);

    boolean existsByEmail(String email);

    /**
     * VULNERABILIDAD SIMULADA: búsqueda por contraseña en MD5.
     * En una app real insegura, este sería el método de autenticación.
     * Demuestra por qué almacenar MD5 es peligroso — se puede comparar directamente.
     */
    @Query("SELECT u FROM InsecureUserEntity u WHERE u.passwordHash = :hash")
    Optional<InsecureUserEntity> findByPasswordHashForDemo(@Param("hash") String hash);

    /**
     * Simula una búsqueda que un atacante haría para encontrar usuarios
     * que comparten la misma contraseña (mismo hash MD5 = misma password).
     */
    @Query("SELECT u FROM InsecureUserEntity u WHERE u.passwordHash = :hash")
    List<InsecureUserEntity> findUsersWithSamePassword(@Param("hash") String hash);
}
