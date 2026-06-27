package com.datashield.infrastructure.persistence.repository;

import com.datashield.infrastructure.persistence.entity.SecureUserEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface SecureUserRepository extends JpaRepository<SecureUserEntity, Long> {

    Optional<SecureUserEntity> findByEmail(String email);

    boolean existsByEmail(String email);
}
