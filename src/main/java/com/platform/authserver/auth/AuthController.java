package com.platform.authserver.auth;

import com.platform.authserver.jwt.JwtService;
import com.platform.authserver.token.ConcurrentRotationException;
import com.platform.authserver.token.CookieFactory;
import com.platform.authserver.token.RefreshTokenService;
import com.platform.authserver.token.ReuseDetectedException;
import com.platform.authserver.user.User;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(AuthController.class);

    private final RefreshTokenService refreshTokenService;
    private final JwtService jwtService;
    private final CookieFactory cookieFactory;
    private final KeycloakLogoutClient keycloakLogoutClient;

    public AuthController(RefreshTokenService refreshTokenService,
                          JwtService jwtService,
                          CookieFactory cookieFactory,
                          KeycloakLogoutClient keycloakLogoutClient) {
        this.refreshTokenService = refreshTokenService;
        this.jwtService = jwtService;
        this.cookieFactory = cookieFactory;
        this.keycloakLogoutClient = keycloakLogoutClient;
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(HttpServletRequest request) {
        String raw = readCookie(request);
        if (raw == null) {
            return ResponseEntity.status(401).body(Map.of("error", "no_refresh_token"));
        }
        try {
            RefreshTokenService.Rotated rotated = refreshTokenService.rotate(raw);
            User user = rotated.user();
            String accessToken = jwtService.issueAccessToken(
                    user.getId(), user.getEmail(), user.getName(), user.getRoles(), user.getProvider());

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
