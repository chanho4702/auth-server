package com.platform.authserver.token;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

import java.time.Duration;

@Component
public class CookieFactory {

    public static final String COOKIE_NAME = "refresh_token";

    private final long ttlSeconds;

    public CookieFactory(@Value("${platform.refresh-token-ttl-seconds}") long ttlSeconds) {
        this.ttlSeconds = ttlSeconds;
    }

    public ResponseCookie refreshCookie(String rawToken) {
        return ResponseCookie.from(COOKIE_NAME, rawToken)
                .httpOnly(true)
                .secure(false) // dev(localhost). 운영 https에서는 true.
                .sameSite("Lax")
                .path("/api/auth")
                .maxAge(Duration.ofSeconds(ttlSeconds))
                .build();
    }

    public ResponseCookie deleteCookie() {
        return ResponseCookie.from(COOKIE_NAME, "")
                .httpOnly(true)
                .secure(false)
                .sameSite("Lax")
                .path("/api/auth")
                .maxAge(0)
                .build();
    }
}
