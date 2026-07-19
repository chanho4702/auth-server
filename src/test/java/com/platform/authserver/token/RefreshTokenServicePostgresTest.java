package com.platform.authserver.token;

import com.platform.authserver.TestOAuth2ClientConfig;
import com.platform.authserver.user.User;
import com.platform.authserver.user.UserRepository;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.TestPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.Instant;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static org.assertj.core.api.Assertions.*;

/**
 * 실 Postgres 검증 — H2 슬라이스 테스트가 못 보는 것들:
 * 동시 rotate 경쟁, noRollbackFor 커밋 동작, V3 마이그레이션(Flyway on).
 * test 프로필을 쓰지 않는다(프로필이 H2+Flyway off 로 바꿔버린다).
 */
@Testcontainers
@SpringBootTest
@Import(TestOAuth2ClientConfig.class)
@TestPropertySource(properties = {"eureka.client.enabled=false"})
class RefreshTokenServicePostgresTest {

    @Container
    @ServiceConnection
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:16");

    @Autowired RefreshTokenService service;
    @Autowired UserRepository userRepository;
    @Autowired RefreshTokenRepository tokenRepository;

    @AfterEach
    void clean() {
        tokenRepository.deleteAll();
        userRepository.deleteAll();
    }

    private User newUser() {
        User u = new User("kc-sub-pg-" + System.nanoTime());
        u.setRoles(List.of("USER"));
        return userRepository.save(u);
    }

    @Test
    void concurrentRotateLeavesExactlyOneLiveToken() throws Exception {
        User u = newUser();
        var issued = service.issue(u, "kc-id", "kc-rt");

        var barrier = new CyclicBarrier(2);
        Callable<Object> attempt = () -> {
            barrier.await();
            try {
                return service.rotate(issued.rawToken());
            } catch (RuntimeException e) {
                return e;
            }
        };
        ExecutorService pool = Executors.newFixedThreadPool(2);
        List<Object> results;
        try {
            results = pool.invokeAll(List.of(attempt, attempt)).stream()
                    .map(f -> {
                        try { return f.get(); } catch (Exception e) { throw new IllegalStateException(e); }
                    }).toList();
        } finally {
            pool.shutdown();
        }

        // 정확히 1승 1패 — 패자는 경쟁 관용(도난 오판 아님)
        assertThat(results).filteredOn(r -> r instanceof RefreshTokenService.Rotated).hasSize(1);
        assertThat(results).filteredOn(r -> r instanceof ConcurrentRotationException).hasSize(1);
        // DB: 살아있는 토큰 정확히 1개, 가족 생존
        assertThat(tokenRepository.findAll()).filteredOn(t -> !t.isRevoked()).hasSize(1);
    }

    @Test
    void reuseWithinGraceKeepsFamilyAlive() {
        User u = newUser();
        var issued = service.issue(u, "kc-id", "kc-rt");
        var rotated = service.rotate(issued.rawToken());

        assertThatThrownBy(() -> service.rotate(issued.rawToken()))
                .isInstanceOf(ConcurrentRotationException.class);
        assertThatCode(() -> service.rotate(rotated.newRawToken())).doesNotThrowAnyException();
    }

    @Test
    void reuseAfterGraceRevokesFamilyAndCommitsDespiteException() {
        User u = newUser();
        var issued = service.issue(u, "kc-id", "kc-rt");
        service.rotate(issued.rawToken());

        RefreshToken old = tokenRepository.findByTokenHash(RefreshTokenService.sha256(issued.rawToken())).orElseThrow();
        old.setReplacedAt(Instant.now().minusSeconds(120)); // grace(30초) 밖
        tokenRepository.save(old);

        assertThatThrownBy(() -> service.rotate(issued.rawToken()))
                .isInstanceOf(ReuseDetectedException.class);

        // 핵심(§1 롤백 버그 회귀 방지): 예외에도 불구하고 가족 폐기가 '커밋'되어 있어야 한다.
        // 이 조회는 별도 트랜잭션 — 롤백됐다면 살아있는 토큰이 보인다.
        assertThat(tokenRepository.findAll()).allMatch(RefreshToken::isRevoked);
    }

    @Test
    void disabledUserAndExpiredFamilyAreRejected() {
        User u = newUser();
        var issued = service.issue(u, "kc-id", "kc-rt");
        u.setEnabled(false);
        userRepository.save(u);
        assertThatThrownBy(() -> service.rotate(issued.rawToken()))
                .isInstanceOf(IllegalArgumentException.class);

        User u2 = newUser();
        var issued2 = service.issue(u2, "kc-id", "kc-rt");
        RefreshToken t = tokenRepository.findByTokenHash(RefreshTokenService.sha256(issued2.rawToken())).orElseThrow();
        t.setFamilyCreatedAt(Instant.now().minusSeconds(7776000L + 60));
        tokenRepository.save(t);
        assertThatThrownBy(() -> service.rotate(issued2.rawToken()))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
