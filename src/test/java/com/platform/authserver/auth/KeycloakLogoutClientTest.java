package com.platform.authserver.auth;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.net.ServerSocket;

import static org.assertj.core.api.Assertions.assertThat;

class KeycloakLogoutClientTest {

    @Test
    @Timeout(15) // 타임아웃 미설정이면 read가 무한 대기 → 이 테스트가 행 재현이자 회귀 방지
    void logoutReturnsInsteadOfHangingWhenKeycloakStalls() throws Exception {
        // accept 는 OS 백로그가 받아주지만 아무도 응답하지 않는 서버 — KC 행(hang) 시뮬레이션
        try (ServerSocket stalled = new ServerSocket(0)) {
            var client = new KeycloakLogoutClient(
                    "http://localhost:" + stalled.getLocalPort() + "/realms/x", "cid", "secret");

            long start = System.nanoTime();
            client.logout("some-refresh-token"); // best-effort — 예외는 삼키고 복귀해야 한다
            long elapsedMs = (System.nanoTime() - start) / 1_000_000;

            assertThat(elapsedMs).isLessThan(10_000); // connect 2s + read 3s + 여유
        }
    }
}
