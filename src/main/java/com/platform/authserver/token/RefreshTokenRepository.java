package com.platform.authserver.token;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {
    Optional<RefreshToken> findByTokenHash(String tokenHash);

    // @Param 명시: 런타임이 -parameters 없이 컴파일돼도 named param(:familyId)을 바인딩할 수 있게 한다.
    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("update RefreshToken t set t.revoked = true where t.familyId = :familyId")
    void revokeFamily(@Param("familyId") UUID familyId);

    // 조건부 UPDATE = check-and-set의 DB 원자 연산. 동시 rotate 중 정확히 한 요청만 1을 받는다.
    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("update RefreshToken t set t.revoked = true, t.replacedBy = :nextId, t.replacedAt = :now " +
           "where t.id = :id and t.revoked = false")
    int markRotated(@Param("id") UUID id, @Param("nextId") UUID nextId, @Param("now") Instant now);

    // 가족 단위 삭제 — 가족의 '최신' 만료가 cutoff 를 지난 경우만. 폐기된 옛 행은 재사용 탐지의
    // 증거물이므로 가족이 살아있는 동안은 절대 지우지 않는다(보존 기간 = 탐지 유효 기간).
    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("delete from RefreshToken t where t.familyId in " +
           "(select t2.familyId from RefreshToken t2 group by t2.familyId having max(t2.expiresAt) < :cutoff)")
    int deleteDeadFamilies(@Param("cutoff") Instant cutoff);
}
