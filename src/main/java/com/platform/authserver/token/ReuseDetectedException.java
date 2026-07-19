package com.platform.authserver.token;

import java.util.UUID;

/** RT 재사용 탐지 = 계정 탈취 의심. 로깅·알림용으로 소유자/가족 식별자를 실어 던진다. */
public class ReuseDetectedException extends RuntimeException {

    private final Long userId;
    private final UUID familyId;

    public ReuseDetectedException(String message, Long userId, UUID familyId) {
        super(message);
        this.userId = userId;
        this.familyId = familyId;
    }

    public Long getUserId() {
        return userId;
    }

    public UUID getFamilyId() {
        return familyId;
    }
}
