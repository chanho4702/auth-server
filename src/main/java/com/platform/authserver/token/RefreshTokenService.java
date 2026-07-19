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

    @Transactional
    public Issued issue(User user, String kcIdToken, String kcRefreshToken) {
        String raw = newRawToken();
        UUID familyId = UUID.randomUUID();
        persist(user.getId(), raw, familyId, kcIdToken, kcRefreshToken);
        return new Issued(raw, kcIdToken);
    }

    @Transactional(noRollbackFor = ReuseDetectedException.class)
    public Rotated rotate(String rawToken) {
        RefreshToken current = tokenRepository.findByTokenHash(sha256(rawToken))
                .orElseThrow(() -> new IllegalArgumentException("알 수 없는 refresh token"));

        if (current.isRevoked()) {
            if (current.getReplacedBy() != null) {
                // 폐기되고 이미 교체(superseded)된 토큰의 재사용 = 도난 → 패밀리 전체 폐기
                tokenRepository.revokeFamily(current.getFamilyId());
                // noRollbackFor: 이 예외는 가족 폐기를 커밋한 채 전파되어야 한다(롤백되면 탐지가 무효).
                throw new ReuseDetectedException("refresh token 재사용 탐지",
                        current.getUserId(), current.getFamilyId());
            }
            // 패밀리 폐기로 부수적으로 무효화된 최신 토큰 → 단순 무효
            throw new IllegalArgumentException("유효하지 않은 refresh token");
        }
        if (current.getExpiresAt().isBefore(Instant.now())) {
            throw new IllegalArgumentException("만료된 refresh token");
        }

        User user = userRepository.findById(current.getUserId())
                .orElseThrow(() -> new IllegalArgumentException("사용자 없음"));

        String newRaw = newRawToken();
        RefreshToken next = persist(user.getId(), newRaw, current.getFamilyId(),
                current.getKcIdToken(), current.getKcRefreshToken());
        current.setRevoked(true);
        current.setReplacedBy(next.getId());
        tokenRepository.save(current);

        return new Rotated(user, newRaw, current.getKcIdToken());
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

    private RefreshToken persist(Long userId, String raw, UUID familyId, String kcIdToken, String kcRefreshToken) {
        RefreshToken token = new RefreshToken(
                userId, sha256(raw), familyId, kcIdToken, kcRefreshToken, Instant.now().plusSeconds(ttlSeconds));
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
