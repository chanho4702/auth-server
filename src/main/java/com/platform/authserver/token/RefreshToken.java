package com.platform.authserver.token;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "refresh_tokens")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED) // JPA 전용 기본 생성자
public class RefreshToken {

    @Id
    private UUID id;

    @Column(name = "user_id", nullable = false)
    private Long userId;

    @Column(name = "token_hash", nullable = false, unique = true)
    private String tokenHash;

    @Column(name = "family_id", nullable = false)
    private UUID familyId;

    @Setter
    @Column(name = "replaced_by")
    private UUID replacedBy;

    @Column(name = "kc_id_token", columnDefinition = "TEXT")
    private String kcIdToken;

    // 백채널 로그아웃용 Keycloak refresh_token. rotate 시 패밀리 내내 승계된다.
    @Column(name = "kc_refresh_token", columnDefinition = "TEXT")
    private String kcRefreshToken;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Setter
    @Column(nullable = false)
    private boolean revoked = false;

    // rotate 선점 시각. grace 판정 기준 — markRotated 쿼리가 채우고, 테스트만 setter로 조작한다.
    @Setter
    @Column(name = "replaced_at")
    private Instant replacedAt;

    // 가족 최초 생성 시각. rotate 시 승계 — 절대 세션 상한 판정 기준.
    @Setter
    @Column(name = "family_created_at", nullable = false)
    private Instant familyCreatedAt;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    public RefreshToken(Long userId, String tokenHash, UUID familyId,
                        String kcIdToken, String kcRefreshToken, Instant expiresAt, Instant familyCreatedAt) {
        this.id = UUID.randomUUID();
        this.userId = userId;
        this.tokenHash = tokenHash;
        this.familyId = familyId;
        this.kcIdToken = kcIdToken;
        this.kcRefreshToken = kcRefreshToken;
        this.expiresAt = expiresAt;
        this.familyCreatedAt = familyCreatedAt;
        this.createdAt = Instant.now();
    }
}
