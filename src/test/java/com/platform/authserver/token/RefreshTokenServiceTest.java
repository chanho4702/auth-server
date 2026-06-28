package com.platform.authserver.token;

import com.platform.authserver.user.User;
import com.platform.authserver.user.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest; // Spring Boot 4: 새 패키지(+ testImpl spring-boot-data-jpa-test)
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.List;

import static org.assertj.core.api.Assertions.*;

@DataJpaTest
@ActiveProfiles("test")
@Import(RefreshTokenService.class)
class RefreshTokenServiceTest {

    @Autowired RefreshTokenService service;
    @Autowired UserRepository userRepository;
    @Autowired RefreshTokenRepository tokenRepository;

    private User newUser() {
        User u = new User("kc-sub-1");
        u.setRoles(List.of("USER"));
        return userRepository.save(u);
    }

    @Test
    void rotateReturnsNewTokenAndRevokesOld() {
        // ttl 주입(슬라이스 테스트라 @Value 미적용)
        ReflectionTestUtils.setField(service, "ttlSeconds", 1209600L);
        User u = newUser();
        var issued = service.issue(u, "kc-id-token", "kc-refresh-token");

        var rotated = service.rotate(issued.rawToken());

        assertThat(rotated.user().getId()).isEqualTo(u.getId());
        assertThat(rotated.newRawToken()).isNotEqualTo(issued.rawToken());
        assertThat(rotated.kcIdToken()).isEqualTo("kc-id-token");
        // 백채널 로그아웃용 KC refresh_token 은 rotate 후에도 회수 가능해야 한다(패밀리 승계).
        assertThat(service.revokeFamilyByRawToken(rotated.newRawToken())).isEqualTo("kc-refresh-token");
        // 옛 토큰 재사용은 이제 도난으로 간주
        assertThatThrownBy(() -> service.rotate(issued.rawToken()))
                .isInstanceOf(ReuseDetectedException.class);
    }

    @Test
    void reuseDetectionRevokesWholeFamily() {
        ReflectionTestUtils.setField(service, "ttlSeconds", 1209600L);
        User u = newUser();
        var issued = service.issue(u, "kc-id-token", "kc-refresh-token");
        var rotated = service.rotate(issued.rawToken()); // 회전 1회

        // 폐기된 옛 토큰 재사용 → 패밀리 전체 폐기
        assertThatThrownBy(() -> service.rotate(issued.rawToken()))
                .isInstanceOf(ReuseDetectedException.class);
        // 패밀리가 폐기됐으므로 방금 회전한 정상 토큰도 더는 못 씀
        assertThatThrownBy(() -> service.rotate(rotated.newRawToken()))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void invalidTokenRejected() {
        ReflectionTestUtils.setField(service, "ttlSeconds", 1209600L);
        assertThatThrownBy(() -> service.rotate("not-a-real-token"))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
