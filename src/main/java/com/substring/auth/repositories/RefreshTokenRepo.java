package com.substring.auth.repositories;

import com.substring.auth.entities.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface RefreshTokenRepo extends JpaRepository<RefreshToken, UUID> {


    Optional<RefreshToken> findByJti(String jti);
}
