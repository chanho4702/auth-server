package com.platform.authserver.token;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

import java.time.Duration;

@Component
public class CookieFactory {

    public static final String COOKIE_NAME = "refresh_token";

    private final long ttlSeconds;
    // dev(localhost)=false, 운영 https=true (COOKIE_SECURE env).
    // SameSite=Lax는 프론트와 게이트웨이가 same-site라는 전제 — cross-site 배포 시 None+Secure 필요.
    private final boolean secure;

    public CookieFactory(@Value("${platform.refresh-token-ttl-seconds}") long ttlSeconds,
                         @Value("${platform.cookie-secure:false}") boolean secure) {
        this.ttlSeconds = ttlSeconds;
        this.secure = secure;
    }

    public ResponseCookie refreshCookie(String rawToken) {
        return ResponseCookie.from(COOKIE_NAME, rawToken)
                .httpOnly(true)
                .secure(secure)
                .sameSite("Lax")
                .path("/api/auth")
                .maxAge(Duration.ofSeconds(ttlSeconds))
                .build();
    }

    public ResponseCookie deleteCookie() {
        return ResponseCookie.from(COOKIE_NAME, "")
                .httpOnly(true)
                .secure(secure)
                .sameSite("Lax")
                .path("/api/auth")
                .maxAge(0)
                .build();
    }
}
