package com.platform.authserver.pat;

/**
 * 없는 토큰이거나 남의 토큰 — 둘 다 404 {@code {"error":"not_found"}}.
 * 소유자가 아닌 요청에 403을 주면 "그 id의 토큰이 존재한다"는 사실이 새므로 구분하지 않는다.
 */
public class TokenNotFoundException extends RuntimeException {
    public TokenNotFoundException(String message) {
        super(message);
    }
}
