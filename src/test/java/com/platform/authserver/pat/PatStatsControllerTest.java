package com.platform.authserver.pat;

import com.platform.authserver.TestOAuth2ClientConfig;
import com.platform.authserver.token.RefreshTokenService;
import com.platform.authserver.user.User;
import com.platform.authserver.user.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;

import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * `/internal/pat/stats` — 관리자 대시보드용 집계. 배선은 `/internal/pat/exchange`와 같다
 * (내부 시크릿 헤더, 게이트웨이가 라우팅하지 않는 경로).
 */
@SpringBootTest
@ActiveProfiles("test")
@Import(TestOAuth2ClientConfig.class)
@TestPropertySource(properties = "platform.agent.internal-secret=test-internal-secret")
class PatStatsControllerTest {

    private static final String SECRET_HEADER = "X-Internal-Secret";
    private static final String SECRET = "test-internal-secret";

    @Autowired WebApplicationContext context;
    @Autowired PersonalAccessTokenRepository tokenRepository;
    @Autowired UserRepository userRepository;

    MockMvc mvc;

    @BeforeEach
    void setup() {
        mvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
        tokenRepository.deleteAll();
        userRepository.deleteAll();
    }

    private User newUser() {
        User u = new User("kc-stats-" + System.nanoTime());
        u.setRoles(List.of("USER"));
        return userRepository.save(u);
    }

    private void persist(User owner, Instant expiresAt, boolean revoked) {
        String raw = PersonalAccessTokenService.TOKEN_PREFIX + UUID.randomUUID();
        PersonalAccessToken token = new PersonalAccessToken(owner.getId(), "라벨",
                RefreshTokenService.sha256(raw), raw.substring(raw.length() - 4),
                List.of(PatScopes.WIKI_READ), Instant.now(), expiresAt);
        if (revoked) {
            token.revoke(Instant.now());
        }
        tokenRepository.save(token);
    }

    @Test
    void counts_only_active_tokens_distinct_users_and_the_seven_day_window() throws Exception {
        Instant now = Instant.now();
        User alice = newUser();
        User bob = newUser();
        User carol = newUser();

        persist(alice, now.plus(30, ChronoUnit.DAYS), false);   // 활성
        persist(alice, now.plus(3, ChronoUnit.DAYS), false);    // 활성 + 7일 내 만료
        persist(bob, now.plus(6, ChronoUnit.HOURS), false);     // 활성 + 7일 내 만료
        persist(bob, now.minus(1, ChronoUnit.DAYS), false);     // 만료 — 제외
        persist(carol, now.plus(30, ChronoUnit.DAYS), true);    // 폐기 — 제외(사용자 수에서도)

        mvc.perform(get("/internal/pat/stats").header(SECRET_HEADER, SECRET))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.activeTokens").value(3))
                .andExpect(jsonPath("$.usersWithTokens").value(2))
                .andExpect(jsonPath("$.expiringWithin7Days").value(2))
                // 계약은 이 세 필드뿐 — 대시보드가 다른 필드를 기대하지 않게 고정한다.
                .andExpect(jsonPath("$.length()").value(3));
    }

    @Test
    void empty_database_returns_zeros() throws Exception {
        mvc.perform(get("/internal/pat/stats").header(SECRET_HEADER, SECRET))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.activeTokens").value(0))
                .andExpect(jsonPath("$.usersWithTokens").value(0))
                .andExpect(jsonPath("$.expiringWithin7Days").value(0));
    }

    @Test
    void wrong_or_missing_internal_secret_is_403() throws Exception {
        mvc.perform(get("/internal/pat/stats").header(SECRET_HEADER, "wrong-secret"))
                .andExpect(status().isForbidden());
        mvc.perform(get("/internal/pat/stats"))
                .andExpect(status().isForbidden());
    }
}
