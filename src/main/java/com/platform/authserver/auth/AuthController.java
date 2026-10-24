package com.platform.authserver.auth;

import com.platform.authserver.jwt.JwtService;
import com.platform.authserver.token.ConcurrentRotationException;
import com.platform.authserver.token.CookieFactory;
import com.platform.authserver.token.RefreshTokenService;
import com.platform.authserver.token.ReuseDetectedException;
import com.platform.authserver.user.User;
import com.platform.authserver.user.UserService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(AuthController.class);

    private final RefreshTokenService refreshTokenService;
    private final JwtService jwtService;
    private final CookieFactory cookieFactory;
    private final KeycloakLogoutClient keycloakLogoutClient;
    private final KeycloakAccountClient keycloakAccounts;
    private final UserService userService;
    private final Duration maxStale;

    public AuthController(RefreshTokenService refreshTokenService,
                          JwtService jwtService,
                          CookieFactory cookieFactory,
                          KeycloakLogoutClient keycloakLogoutClient,
                          KeycloakAccountClient keycloakAccounts,
                          UserService userService,
                          @Value("${platform.keycloak-sync.max-stale-seconds:86400}") long maxStaleSeconds) {
        this.refreshTokenService = refreshTokenService;
        this.jwtService = jwtService;
        this.cookieFactory = cookieFactory;
        this.keycloakLogoutClient = keycloakLogoutClient;
        this.keycloakAccounts = keycloakAccounts;
        this.userService = userService;
        this.maxStale = Duration.ofSeconds(Math.max(0, maxStaleSeconds));
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(HttpServletRequest request) {
        String raw = readCookie(request);
        if (raw == null) {
            return ResponseEntity.status(401).body(Map.of("error", "no_refresh_token"));
        }
        // ① 회전 전에 Keycloak 계정을 재확인한다(점검 M1) — HTTP 호출을 회전 트랜잭션 밖에 둔다.
        List<String> freshRoles = null;
        Optional<User> owner = refreshTokenService.ownerOf(raw);
        if (owner.isPresent()) {
            User u = owner.get();
            KeycloakAccountClient.Verdict verdict = keycloakAccounts.check(u.getKeycloakSub());
            switch (verdict.kind()) {
                case DISABLED, GONE -> {
                    // Keycloak에서 잠기거나 지워진 계정 — 이 토큰만이 아니라 그 사람의 RT 전부를 폐기한다(B3 일부).
                    int revoked = userService.closeSessions(u.getId());
                    keycloakAccounts.evict(u.getKeycloakSub());
                    log.warn("Keycloak 계정 {} — 리프레시 거부, 리프레시 토큰 {}개 폐기: userId={}",
                            verdict.kind() == KeycloakAccountClient.Verdict.Kind.GONE ? "삭제" : "비활성",
                            revoked, u.getId());
                    return unauthorizedWithCookieDelete();
                }
                case UNAVAILABLE -> {
                    // 가용성 vs 안전: 구성원 상태의 정본은 org이고(정지·퇴사는 org가 users.enabled로 이미 닫는다),
                    // Keycloak 확인은 롤 회수·KC 직접 잠금을 잡는 보조 장치다. 그래서 KC가 잠깐 죽었다고 전원을 로그아웃시키지
                    // 않고, 마지막으로 맞춘 roles가 max-stale(기본 24시간) 안이면 그대로 쓴다. 그보다 오래됐으면 503 —
                    // 쿠키는 지우지 않으므로 KC가 돌아오면 같은 쿠키로 바로 회복된다.
                    if (!rolesFresh(u)) {
                        log.warn("Keycloak 확인 불가 + roles가 {}보다 오래됨 — 리프레시 보류(503): userId={}", maxStale, u.getId());
                        return ResponseEntity.status(503).body(Map.of("error", "auth_unavailable"));
                    }
                }
                case ACTIVE -> freshRoles = verdict.roles();
                case SKIPPED -> { /* 미설정·에이전트 — 로그인 때 roles 그대로 */ }
            }
        }
        try {
            RefreshTokenService.Rotated rotated = refreshTokenService.rotate(raw);
            User user = rotated.user();
            List<String> roles = user.getRoles();
            if (freshRoles != null) {
                userService.applyKeycloakRoles(user.getId(), freshRoles);
                roles = freshRoles;
            }
            String accessToken = jwtService.issueAccessToken(
                    user.getId(), user.getEmail(), user.getName(), roles, user.getProvider());

            Map<String, Object> body = new HashMap<>();
            body.put("accessToken", accessToken);
            return ResponseEntity.ok()
                    .header(HttpHeaders.SET_COOKIE, cookieFactory.refreshCookie(rotated.newRawToken()).toString())
                    .body(body);
        } catch (ReuseDetectedException e) {
            // 최고 등급 보안 이벤트 — 탈취 의심. 응답은 다른 실패와 동일(정보 노출 최소화).
            log.warn("RT 재사용 탐지 — 계정 탈취 의심. userId={}, familyId={}", e.getUserId(), e.getFamilyId());
            return unauthorizedWithCookieDelete();
        } catch (ConcurrentRotationException e) {
            // 멀티탭 경쟁 패배 — 승자가 심은 새 쿠키를 지우면 안 되므로 Set-Cookie 없이 401만.
            log.debug("RT rotate 경쟁 패배: {}", e.getMessage());
            return ResponseEntity.status(401).body(Map.of("error", "invalid_refresh_token"));
        } catch (IllegalArgumentException e) {
            log.debug("무효 RT: {}", e.getMessage());
            return unauthorizedWithCookieDelete();
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest request) {
        String raw = readCookie(request);
        // 자체 RT 패밀리 폐기 + KC refresh_token 회수
        String kcRefreshToken = refreshTokenService.revokeFamilyByRawToken(raw);
        // KC SSO 세션을 서버-서버로 종료(best-effort). 브라우저 리다이렉트 불필요.
        keycloakLogoutClient.logout(kcRefreshToken);

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, cookieFactory.deleteCookie().toString())
                .body(new HashMap<String, Object>());
    }

    /** 마지막으로 Keycloak과 맞춘 roles(없으면 마지막 로그인)가 max-stale 안인가. */
    private boolean rolesFresh(User user) {
        Instant base = user.getRolesSyncedAt() != null ? user.getRolesSyncedAt() : user.getLastLoginAt();
        return base != null && !base.plus(maxStale).isBefore(Instant.now());
    }

    private String readCookie(HttpServletRequest request) {
        if (request.getCookies() == null) {
            return null;
        }
        for (var c : request.getCookies()) {
            if (CookieFactory.COOKIE_NAME.equals(c.getName())) {
                return c.getValue();
            }
        }
        return null;
    }

    private ResponseEntity<?> unauthorizedWithCookieDelete() {
        return ResponseEntity.status(401)
                .header(HttpHeaders.SET_COOKIE, cookieFactory.deleteCookie().toString())
                .body(Map.of("error", "invalid_refresh_token"));
    }
}
