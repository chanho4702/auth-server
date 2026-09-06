package com.platform.authserver.pat;

import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * 개인 API 토큰. 원문은 발급 응답에 한 번만 실리고 DB에는 SHA-256 해시만 남는다
 * ({@code RefreshTokenService.sha256}). {@code tokenHint}는 목록에서 토큰을 식별하기 위한
 * 원문 뒤 4자다.
 *
 * <p>폐기는 행 삭제가 아니라 {@code revokedAt} 세팅이다 — 감사 흔적을 남기고,
 * 90일 뒤 {@link PatCleanupJob}이 물리 삭제한다.
 */
@Entity
@Table(name = "personal_access_tokens")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED) // JPA 전용 기본 생성자
public class PersonalAccessToken {

    @Id
    private UUID id;

    @Column(name = "user_id", nullable = false)
    private Long userId;

    @Column(nullable = false, length = 100)
    private String label;

    @Column(name = "token_hash", nullable = false, unique = true, length = 64)
    private String tokenHash;

    @Column(name = "token_hint", nullable = false, length = 8)
    private String tokenHint;

    /**
     * 이 토큰이 허용된 스코프. 저장은 쉼표 구분 한 컬럼({@link PatScopesConverter}),
     * 값은 항상 정규화(중복 제거·정렬)된 상태다. 빈 목록은 만들 수 없다
     * ({@link PatScopes#normalize}가 생성 경로에서 막는다).
     */
    @Convert(converter = PatScopesConverter.class)
    @Column(nullable = false, length = 255)
    private List<String> scopes;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(name = "last_used_at")
    private Instant lastUsedAt;

    @Column(name = "revoked_at")
    private Instant revokedAt;

    public PersonalAccessToken(Long userId, String label, String tokenHash, String tokenHint,
                               List<String> scopes, Instant createdAt, Instant expiresAt) {
        this.id = UUID.randomUUID();
        this.userId = userId;
        this.label = label;
        this.tokenHash = tokenHash;
        this.tokenHint = tokenHint;
        // 생성자에서 정규화한다 — 호출부마다 normalize를 기억해야 하면 언젠가 빠진다.
        this.scopes = PatScopes.normalize(scopes);
        this.createdAt = createdAt;
        this.expiresAt = expiresAt;
    }

    public boolean isRevoked() {
        return revokedAt != null;
    }

    public boolean isExpired(Instant now) {
        return !expiresAt.isAfter(now);
    }

    public boolean isActive(Instant now) {
        return !isRevoked() && !isExpired(now);
    }

    /** 폐기는 멱등 — 이미 폐기된 토큰의 시각을 덮어쓰지 않는다(최초 폐기 시점이 감사 기록). */
    public void revoke(Instant now) {
        if (revokedAt == null) {
            this.revokedAt = now;
        }
    }

    /**
     * 교환 성공 표시. 직전 갱신 후 {@code throttleSeconds}가 지났을 때만 갱신하고,
     * 갱신 여부를 반환한다 — 게이트웨이 캐시 TTL(60초)과 맞춰 매 요청 UPDATE를 피한다.
     */
    /**
     * 갱신은 {@link #touchLastUsed}가 전담한다. 이 setter는 스로틀 경계를 검증하는
     * 테스트가 과거 시각을 심을 때만 쓰라고 패키지 전용으로 열어 둔 것이다
     * ({@code RefreshToken.replacedAt}와 같은 관례).
     */
    void setLastUsedAt(Instant lastUsedAt) {
        this.lastUsedAt = lastUsedAt;
    }

    public boolean touchLastUsed(Instant now, long throttleSeconds) {
        if (lastUsedAt != null && lastUsedAt.isAfter(now.minusSeconds(throttleSeconds))) {
            return false;
        }
        this.lastUsedAt = now;
        return true;
    }
}
