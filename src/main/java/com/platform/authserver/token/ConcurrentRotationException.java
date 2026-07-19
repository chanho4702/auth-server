package com.platform.authserver.token;

/**
 * rotate 경쟁 패배(grace 이내 재사용) — 멀티탭 등 정상 시나리오로 관용한다.
 * 도난(ReuseDetectedException)과 달리 가족을 살려두고, 쿠키도 지우지 않는다.
 */
public class ConcurrentRotationException extends RuntimeException {
    public ConcurrentRotationException(String message) {
        super(message);
    }
}
