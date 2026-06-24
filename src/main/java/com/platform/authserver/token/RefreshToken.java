package com.platform.authserver.token;

import jakarta.persistence.*;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "refresh_tokens")
public class RefreshToken {

    @Id
    private UUID id;

    @Column(name = "user_id", nullable = false)
    private Long userId;

    @Column(name = "token_hash", nullable = false, unique = true)
    private String tokenHash;

    @Column(name = "family_id", nullable = false)
    private UUID familyId;

    @Column(name = "replaced_by")
    private UUID replacedBy;

    @Column(name = "kc_id_token", columnDefinition = "TEXT")
    private String kcIdToken;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(nullable = false)
    private boolean revoked = false;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    protected RefreshToken() {
    }

    public RefreshToken(Long userId, String tokenHash, UUID familyId, String kcIdToken, Instant expiresAt) {
        this.id = UUID.randomUUID();
        this.userId = userId;
        this.tokenHash = tokenHash;
        this.familyId = familyId;
        this.kcIdToken = kcIdToken;
        this.expiresAt = expiresAt;
        this.createdAt = Instant.now();
    }

    public UUID getId() { return id; }
    public Long getUserId() { return userId; }
    public UUID getFamilyId() { return familyId; }
    public String getKcIdToken() { return kcIdToken; }
    public Instant getExpiresAt() { return expiresAt; }
    public boolean isRevoked() { return revoked; }
    public UUID getReplacedBy() { return replacedBy; }
    public void setRevoked(boolean revoked) { this.revoked = revoked; }
    public void setReplacedBy(UUID replacedBy) { this.replacedBy = replacedBy; }
}
