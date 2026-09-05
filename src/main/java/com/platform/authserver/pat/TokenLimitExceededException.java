package com.platform.authserver.pat;

/** 사용자당 활성 PAT 한도 초과 — 409 {@code {"error":"token_limit"}}. */
public class TokenLimitExceededException extends RuntimeException {
    public TokenLimitExceededException(String message) {
        super(message);
    }
}
