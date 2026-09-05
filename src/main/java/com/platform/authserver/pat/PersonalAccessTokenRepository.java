package com.platform.authserver.pat;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface PersonalAccessTokenRepository extends JpaRepository<PersonalAccessToken, UUID> {

    List<PersonalAccessToken> findByUserIdOrderByCreatedAtDesc(Long userId);

    Optional<PersonalAccessToken> findByTokenHash(String tokenHash);

    /** 남의 토큰을 건드리지 못하게 소유자까지 조건에 넣는다 — 없으면 404(존재 자체를 노출하지 않는다). */
    Optional<PersonalAccessToken> findByIdAndUserId(UUID id, Long userId);

    @Query("""
            SELECT COUNT(t) FROM PersonalAccessToken t
            WHERE t.userId = :userId AND t.revokedAt IS NULL AND t.expiresAt > :now
            """)
    long countActive(@Param("userId") Long userId, @Param("now") Instant now);

    /** 만료·폐기된 지 cutoff보다 오래된 행을 물리 삭제. 활성 토큰은 절대 지우지 않는다. */
    @Modifying(clearAutomatically = true)
    @Query("""
            DELETE FROM PersonalAccessToken t
            WHERE (t.revokedAt IS NOT NULL AND t.revokedAt < :cutoff)
               OR (t.expiresAt < :cutoff)
            """)
    int deleteStale(@Param("cutoff") Instant cutoff);
}
