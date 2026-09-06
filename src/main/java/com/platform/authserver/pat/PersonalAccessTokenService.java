package com.platform.authserver.pat;

import com.platform.authserver.jwt.JwtService;
import com.platform.authserver.token.RefreshTokenService;
import com.platform.authserver.user.User;
import com.platform.authserver.user.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * 개인 API 토큰(PAT)의 발급·목록·폐기·교환. 원문은 발급 시 딱 한 번 호출부로 돌려주고
 * 저장하지 않는다 — DB에는 {@link RefreshTokenService#sha256(String)} 해시만 남는다.
 *
 * <p>로그에는 userId/tokenId/hint만 남긴다. 원문과 해시는 절대 남기지 않는다.
 */
@Service
public class PersonalAccessTokenService {

    private static final Logger log = LoggerFactory.getLogger(PersonalAccessTokenService.class);

    /** 게이트웨이가 이 접두사만 보고 PAT/플랫폼 JWT를 구분한다. */
    public static final String TOKEN_PREFIX = "chanho_pat_";
    /** 원문 뒤 4자만 저장 — 목록에서 {@code chanho_pat_…ab12}로 식별. */
    static final int HINT_LENGTH = 4;
    static final int MAX_ACTIVE_TOKENS = 25;
    static final int MIN_EXPIRY_DAYS = 1;
    static final int MAX_EXPIRY_DAYS = 365;
    static final int DEFAULT_EXPIRY_DAYS = 90;
    static final int MAX_LABEL_LENGTH = 100;
    /** last_used_at 갱신 최소 간격. 게이트웨이 캐시 TTL(60s)과 맞춘다. */
    static final long LAST_USED_THROTTLE_SECONDS = 60;
    /** {@link #stats()}의 "곧 만료" 기준. 관리자 대시보드 카드가 이 창을 쓴다. */
    static final int EXPIRING_SOON_DAYS = 7;
    private static final String PAT_PROVIDER = "PAT";
    /** 교환 JWT의 스코프 클레임 이름. 게이트웨이 PatScopeWebFilter와 맞춘 계약이다. */
    public static final String SCOPE_CLAIM = "scope";

    private final PersonalAccessTokenRepository tokenRepository;
    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final long patJwtTtlSeconds;
    private final SecureRandom random = new SecureRandom();

    public PersonalAccessTokenService(PersonalAccessTokenRepository tokenRepository,
                                      UserRepository userRepository,
                                      JwtService jwtService,
                                      @Value("${platform.pat-jwt-ttl-seconds}") long patJwtTtlSeconds) {
        this.tokenRepository = tokenRepository;
        this.userRepository = userRepository;
        this.jwtService = jwtService;
        this.patJwtTtlSeconds = patJwtTtlSeconds;
    }

    /** 발급 결과. {@code rawToken}은 이 응답에만 실리고 다시는 조회할 수 없다. */
    public record Created(PersonalAccessToken token, String rawToken) {}

    /** 교환 결과 — 플랫폼 JWT와 그 TTL. */
    public record Exchanged(String accessToken, long expiresInSeconds) {}

    /** 활성 토큰 집계. 활성 = 미폐기 AND 미만료. */
    public record Stats(long activeTokens, long usersWithTokens, long expiringWithin7Days) {}

    @Transactional(readOnly = true)
    public List<PersonalAccessToken> list(long userId) {
        return tokenRepository.findByUserIdOrderByCreatedAtDesc(userId);
    }

    /**
     * 새 토큰 발급. 라벨/만료일 검증은 컨트롤러가 이미 마쳤다고 보고, 여기서는 도메인 규칙인
     * 활성 개수 한도만 본다. 스코프는 엔티티 생성자가 정규화·검증한다
     * ({@link PatScopes#normalize}) — 빈 목록·모르는 값은 여기서도 통과하지 못한다.
     *
     * @throws TokenLimitExceededException 활성 토큰이 {@value #MAX_ACTIVE_TOKENS}개 이상일 때
     * @throws IllegalArgumentException    스코프가 비었거나 허용 집합 밖일 때
     */
    @Transactional
    public Created create(long userId, String label, int expiresInDays, List<String> scopes) {
        Instant now = Instant.now();
        if (tokenRepository.countActive(userId, now) >= MAX_ACTIVE_TOKENS) {
            throw new TokenLimitExceededException(
                    "활성 토큰이 " + MAX_ACTIVE_TOKENS + "개를 넘었습니다");
        }

        String raw = generateRawToken();
        String hint = raw.substring(raw.length() - HINT_LENGTH);
        PersonalAccessToken token = new PersonalAccessToken(
                userId, label, RefreshTokenService.sha256(raw), hint, scopes,
                now, now.plus(Duration.ofDays(expiresInDays)));
        PersonalAccessToken saved = tokenRepository.save(token);

        log.info("PAT 발급: userId={}, tokenId={}, hint={}, scopes={}, expiresAt={}",
                userId, saved.getId(), hint, saved.getScopes(), saved.getExpiresAt());
        return new Created(saved, raw);
    }

    /**
     * 폐기. 남의 토큰이면 존재를 노출하지 않고 404, 이미 폐기됐으면 그대로 성공(멱등).
     *
     * @throws TokenNotFoundException 없는 토큰이거나 다른 사용자의 토큰일 때
     */
    @Transactional
    public void revoke(long userId, UUID tokenId) {
        PersonalAccessToken token = tokenRepository.findByIdAndUserId(tokenId, userId)
                .orElseThrow(() -> new TokenNotFoundException("토큰을 찾을 수 없습니다"));
        boolean alreadyRevoked = token.isRevoked();
        token.revoke(Instant.now());
        if (!alreadyRevoked) {
            log.info("PAT 폐기: userId={}, tokenId={}, hint={}", userId, tokenId, token.getTokenHint());
        }
    }

    /**
     * 원문 PAT → 플랫폼 JWT 교환(클러스터 내부 전용). 없음·만료·폐기·사용자 비활성은 전부
     * 빈 Optional로 같은 401이 되고, 구분은 로그에만 남긴다 — 응답 차이로 유효한 토큰을
     * 가려낼 수 없게 한다.
     */
    @Transactional
    public Optional<Exchanged> exchange(String rawToken) {
        if (rawToken == null || rawToken.isBlank()) {
            return Optional.empty();
        }
        Optional<PersonalAccessToken> found = tokenRepository.findByTokenHash(RefreshTokenService.sha256(rawToken));
        if (found.isEmpty()) {
            log.debug("PAT 교환 실패: 알 수 없는 토큰");
            return Optional.empty();
        }

        PersonalAccessToken token = found.get();
        Instant now = Instant.now();
        if (token.isRevoked()) {
            log.debug("PAT 교환 실패: 폐기된 토큰 tokenId={}", token.getId());
            return Optional.empty();
        }
        if (token.isExpired(now)) {
            log.debug("PAT 교환 실패: 만료된 토큰 tokenId={}", token.getId());
            return Optional.empty();
        }

        Optional<User> user = userRepository.findById(token.getUserId()).filter(User::isEnabled);
        if (user.isEmpty()) {
            log.debug("PAT 교환 실패: 비활성/삭제된 사용자 tokenId={}, userId={}", token.getId(), token.getUserId());
            return Optional.empty();
        }

        // 더티 체킹으로 커밋 시 UPDATE. 스로틀에 걸리면 아예 필드를 건드리지 않으므로 UPDATE도 없다.
        token.touchLastUsed(now, LAST_USED_THROTTLE_SECONDS);

        User u = user.get();
        // scope 클레임은 PAT 교환 JWT에만 실린다 — 세션 JWT(로그인/refresh)는 스코프 개념이 없다.
        // 게이트웨이의 PatScopeWebFilter가 이 클레임으로 경로/메서드를 판정한다.
        String jwt = jwtService.issueAccessToken(
                u.getId(), u.getEmail(), u.getName(), u.getRoles(), PAT_PROVIDER, patJwtTtlSeconds,
                Map.of(SCOPE_CLAIM, token.getScopes()));
        return Optional.of(new Exchanged(jwt, patJwtTtlSeconds));
    }

    /**
     * 관리자 대시보드용 집계(게이트웨이 {@code /api/platform/stats/tokens}가 소비).
     * COUNT 세 번만 돈다 — 캐시는 호출부(게이트웨이, 60초)가 한다.
     */
    @Transactional(readOnly = true)
    public Stats stats() {
        Instant now = Instant.now();
        return new Stats(
                tokenRepository.countAllActive(now),
                tokenRepository.countUsersWithActiveTokens(now),
                tokenRepository.countActiveExpiringBefore(now, now.plus(Duration.ofDays(EXPIRING_SOON_DAYS))));
    }

    /** {@code chanho_pat_} + base64url(SecureRandom 32바이트) = 11 + 43자. */
    private String generateRawToken() {
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        return TOKEN_PREFIX + Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
