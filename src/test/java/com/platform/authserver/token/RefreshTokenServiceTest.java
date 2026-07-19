package com.platform.authserver.token;

import com.platform.authserver.user.User;
import com.platform.authserver.user.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest; // Spring Boot 4: 새 패키지(+ testImpl spring-boot-data-jpa-test)
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.*;

@DataJpaTest
@ActiveProfiles("test")
@Import(RefreshTokenService.class)
class RefreshTokenServiceTest {

    @Autowired RefreshTokenService service;
    @Autowired UserRepository userRepository;
    @Autowired RefreshTokenRepository tokenRepository;

    @BeforeEach
    void injectConfig() {
        // 슬라이스 테스트라 @Value 미적용 — 직접 주입. grace=0: 재사용 즉시 도난 판정(기존 동작 검증용).
        ReflectionTestUtils.setField(service, "ttlSeconds", 1209600L);
        ReflectionTestUtils.setField(service, "graceSeconds", 0L);
        ReflectionTestUtils.setField(service, "absoluteTtlSeconds", 7776000L);
    }

    private User newUser() {
        User u = new User("kc-sub-1");
        u.setRoles(List.of("USER"));
        return userRepository.save(u);
    }

    @Test
    void rotateReturnsNewTokenAndRevokesOld() {
        User u = newUser();
        var issued = service.issue(u, "kc-id-token", "kc-refresh-token");

        var rotated = service.rotate(issued.rawToken());

        assertThat(rotated.user().getId()).isEqualTo(u.getId());
        assertThat(rotated.newRawToken()).isNotEqualTo(issued.rawToken());
        assertThat(rotated.kcIdToken()).isEqualTo("kc-id-token");
        // 백채널 로그아웃용 KC refresh_token 은 rotate 후에도 회수 가능해야 한다(패밀리 승계).
        assertThat(service.revokeFamilyByRawToken(rotated.newRawToken())).isEqualTo("kc-refresh-token");
        // 옛 토큰 재사용은 이제 도난으로 간주(grace=0)
        assertThatThrownBy(() -> service.rotate(issued.rawToken()))
                .isInstanceOf(ReuseDetectedException.class);
    }

    @Test
    void reuseDetectionRevokesWholeFamily() {
        User u = newUser();
        var issued = service.issue(u, "kc-id-token", "kc-refresh-token");
        var rotated = service.rotate(issued.rawToken());

        assertThatThrownBy(() -> service.rotate(issued.rawToken()))
                .isInstanceOf(ReuseDetectedException.class);
        // 패밀리가 폐기됐으므로 방금 회전한 정상 토큰도 더는 못 씀
        assertThatThrownBy(() -> service.rotate(rotated.newRawToken()))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void reuseDetectedExceptionCarriesUserAndFamily() {
        User u = newUser();
        var issued = service.issue(u, "kc-id-token", "kc-refresh-token");
        service.rotate(issued.rawToken());

        assertThatThrownBy(() -> service.rotate(issued.rawToken()))
                .isInstanceOfSatisfying(ReuseDetectedException.class, e -> {
                    assertThat(e.getUserId()).isEqualTo(u.getId());
                    assertThat(e.getFamilyId()).isNotNull();
                });
    }

    @Test
    void markRotatedClaimsTokenExactlyOnce() {
        User u = newUser();
        var issued = service.issue(u, "kc-id-token", "kc-refresh-token");
        RefreshToken t = tokenRepository.findByTokenHash(RefreshTokenService.sha256(issued.rawToken())).orElseThrow();

        int first = tokenRepository.markRotated(t.getId(), UUID.randomUUID(), Instant.now());
        int second = tokenRepository.markRotated(t.getId(), UUID.randomUUID(), Instant.now());

        assertThat(first).isEqualTo(1);
        assertThat(second).isZero();
    }

    @Test
    void reuseWithinGraceIsToleratedAndFamilySurvives() {
        ReflectionTestUtils.setField(service, "graceSeconds", 30L);
        User u = newUser();
        var issued = service.issue(u, "kc-id-token", "kc-refresh-token");
        var rotated = service.rotate(issued.rawToken());

        // 방금(grace 이내) 교체된 토큰 재사용 = 멀티탭 경쟁으로 관용
        assertThatThrownBy(() -> service.rotate(issued.rawToken()))
                .isInstanceOf(ConcurrentRotationException.class);
        // 가족은 생존 — 최신 토큰은 계속 회전 가능
        assertThatCode(() -> service.rotate(rotated.newRawToken())).doesNotThrowAnyException();
    }

    @Test
    void reuseAfterGraceIsTheft() {
        ReflectionTestUtils.setField(service, "graceSeconds", 30L);
        User u = newUser();
        var issued = service.issue(u, "kc-id-token", "kc-refresh-token");
        service.rotate(issued.rawToken());

        // replaced_at 을 grace 밖(2분 전)으로 조작 → 도난 판정
        RefreshToken old = tokenRepository.findByTokenHash(RefreshTokenService.sha256(issued.rawToken())).orElseThrow();
        old.setReplacedAt(Instant.now().minusSeconds(120));
        tokenRepository.save(old);

        assertThatThrownBy(() -> service.rotate(issued.rawToken()))
                .isInstanceOf(ReuseDetectedException.class);
    }

    @Test
    void disabledUserCannotRotate() {
        User u = newUser();
        var issued = service.issue(u, "kc-id-token", "kc-refresh-token");
        u.setEnabled(false);
        userRepository.save(u);

        assertThatThrownBy(() -> service.rotate(issued.rawToken()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("비활성화");
    }

    @Test
    void familyPastAbsoluteTtlCannotRotate() {
        User u = newUser();
        var issued = service.issue(u, "kc-id-token", "kc-refresh-token");
        RefreshToken t = tokenRepository.findByTokenHash(RefreshTokenService.sha256(issued.rawToken())).orElseThrow();
        t.setFamilyCreatedAt(Instant.now().minusSeconds(7776000L + 60)); // 90일 + 1분 전
        tokenRepository.save(t);

        assertThatThrownBy(() -> service.rotate(issued.rawToken()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("절대");
    }

    @Test
    void invalidTokenRejected() {
        assertThatThrownBy(() -> service.rotate("not-a-real-token"))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
