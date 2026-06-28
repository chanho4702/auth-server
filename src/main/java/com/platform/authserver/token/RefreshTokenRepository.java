package com.platform.authserver.token;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;
import java.util.UUID;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {
    Optional<RefreshToken> findByTokenHash(String tokenHash);

    // @Param 명시: 런타임이 -parameters 없이 컴파일돼도 named param(:familyId)을 바인딩할 수 있게 한다.
    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("update RefreshToken t set t.revoked = true where t.familyId = :familyId")
    void revokeFamily(@Param("familyId") UUID familyId);
}
