package com.platform.authserver.token;

import com.platform.authserver.user.User;
import com.platform.authserver.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    public record Issued(String rawToken, String kcIdToken) {}
    public record Rotated(User user, String newRawToken, String kcIdToken) {}

    private static final SecureRandom RANDOM = new SecureRandom();

    private final RefreshTokenRepository tokenRepository;
    private final UserRepository userRepository;

    @Value("${platform.refresh-token-ttl-seconds}")
    private long ttlSeconds;

    @Value("${platform.rotation-grace-seconds}")
    private long graceSeconds;

    @Value("${platform.session-absolute-ttl-seconds}")
    private long absoluteTtlSeconds;

    @Transactional
    public Issued issue(User user, String kcIdToken, String kcRefreshToken) {
        String raw = newRawToken();
        UUID familyId = UUID.randomUUID();
        persist(user.getId(), raw, familyId, kcIdToken, kcRefreshToken, Instant.now());
        return new Issued(raw, kcIdToken);
    }

    @Transactional(noRollbackFor = ReuseDetectedException.class)
    public Rotated rotate(String rawToken) {
        RefreshToken current = tokenRepository.findByTokenHash(sha256(rawToken))
                .orElseThrow(() -> new IllegalArgumentException("알 수 없는 refresh token"));

        if (current.isRevoked()) {
            handleRevoked(current); // 항상 throw
        }
        if (current.getExpiresAt().isBefore(Instant.now())) {
            throw new IllegalArgumentException("만료된 refresh token");
        }
        // sliding 만료 보완: 가족 생성 후 절대 상한을 넘기면 재로그인 유도
        if (Instant.now().isAfter(current.getFamilyCreatedAt().plusSeconds(absoluteTtlSeconds))) {
            throw new IllegalArgumentException("세션 절대 상한 초과");
        }

        User user = userRepository.findById(current.getUserId())
                .orElseThrow(() -> new IllegalArgumentException("사용자 없음"));
        if (!user.isEnabled()) {
            throw new IllegalArgumentException("비활성화된 사용자");
        }

        // 선점(조건부 UPDATE) → INSERT 순서. next ID를 선확정해야 선점 쿼리에 실을 수 있다.
        String newRaw = newRawToken();
        RefreshToken next = new RefreshToken(user.getId(), sha256(newRaw), current.getFamilyId(),
                current.getKcIdToken(), current.getKcRefreshToken(),
                Instant.now().plusSeconds(ttlSeconds), current.getFamilyCreatedAt());

        int claimed = tokenRepository.markRotated(current.getId(), next.getId(), Instant.now());
        if (claimed == 0) {
            // 경쟁 패배 — clearAutomatically 로 컨텍스트가 비워졌으므로 재조회 후 grace 판정
            RefreshToken fresh = tokenRepository.findById(current.getId())
                    .orElseThrow(() -> new IllegalArgumentException("유효하지 않은 refresh token"));
            handleRevoked(fresh); // 항상 throw
        }
        tokenRepository.save(next);

        return new Rotated(user, newRaw, next.getKcIdToken());
    }

    /** 폐기된 토큰 처리: grace 이내 재사용=경쟁 관용, 경과=도난(가족 폐기), 교체 이력 없으면 단순 무효. */
    private void handleRevoked(RefreshToken t) {
        if (t.getReplacedBy() != null) {
            if (t.getReplacedAt() != null
                    && t.getReplacedAt().isAfter(Instant.now().minusSeconds(graceSeconds))) {
                throw new ConcurrentRotationException("grace 이내 재사용 — 멀티탭 경쟁으로 관용");
            }
            // grace 밖 재사용 = 도난 → 패밀리 전체 폐기 (noRollbackFor 로 커밋 보장)
            tokenRepository.revokeFamily(t.getFamilyId());
            throw new ReuseDetectedException("refresh token 재사용 탐지", t.getUserId(), t.getFamilyId());
        }
        // 패밀리 폐기로 부수적으로 무효화된 토큰 → 단순 무효
        throw new IllegalArgumentException("유효하지 않은 refresh token");
    }

    /**
     * 로그아웃: 해당 토큰의 패밀리를 폐기하고 백채널 로그아웃용 Keycloak refresh_token 을 반환(없으면 null).
     * 반환된 refresh_token 으로 KC end_session 을 서버-서버 호출해 SSO 세션을 끊는다.
     */
    @Transactional
    public String revokeFamilyByRawToken(String rawToken) {
        if (rawToken == null) {
            return null;
        }
        return tokenRepository.findByTokenHash(sha256(rawToken))
                .map(t -> {
                    tokenRepository.revokeFamily(t.getFamilyId());
                    return t.getKcRefreshToken();
                })
                .orElse(null);
    }

    private RefreshToken persist(Long userId, String raw, UUID familyId,
                                 String kcIdToken, String kcRefreshToken, Instant familyCreatedAt) {
        RefreshToken token = new RefreshToken(
                userId, sha256(raw), familyId, kcIdToken, kcRefreshToken,
                Instant.now().plusSeconds(ttlSeconds), familyCreatedAt);
        return tokenRepository.save(token);
    }

    private static String newRawToken() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    public static String sha256(String raw) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(raw.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
