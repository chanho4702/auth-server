package com.platform.authserver.pat;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import com.platform.authserver.TestOAuth2ClientConfig;
import com.platform.authserver.token.RefreshTokenService;
import com.platform.authserver.user.User;
import com.platform.authserver.user.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * `/internal/pat/exchange` — 게이트웨이 PAT 필터만 부르는 내부 경로.
 * 인증은 {@code InternalSecretFilter}(시크릿 헤더)가 전담한다.
 */
@SpringBootTest
@ActiveProfiles("test")
@Import(TestOAuth2ClientConfig.class)
@TestPropertySource(properties = "platform.agent.internal-secret=test-internal-secret")
class PatExchangeControllerTest {

    private static final String SECRET_HEADER = "X-Internal-Secret";
    private static final String SECRET = "test-internal-secret";
    /** application.yml 기본값 platform.pat-jwt-ttl-seconds. */
    private static final long PAT_JWT_TTL = 300L;

    @Autowired WebApplicationContext context;
    @Autowired PersonalAccessTokenRepository tokenRepository;
    @Autowired UserRepository userRepository;
    @Autowired PersonalAccessTokenService tokenService;

    MockMvc mvc;
    final ObjectMapper objectMapper = new ObjectMapper();

    User alice;

    @BeforeEach
    void setup() {
        mvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
        tokenRepository.deleteAll();
        userRepository.deleteAll();
        alice = new User("kc-alice-" + System.nanoTime());
        alice.setEmail("alice@demo.com");
        alice.setName("앨리스");
        alice.setRoles(List.of("USER", "ADMIN"));
        alice.setProvider("KEYCLOAK");
        alice = userRepository.save(alice);
    }

    private org.springframework.test.web.servlet.ResultActions exchange(String rawToken, String secret) throws Exception {
        var request = post("/internal/pat/exchange")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"token\":" + objectMapper.writeValueAsString(rawToken) + "}");
        if (secret != null) {
            request = request.header(SECRET_HEADER, secret);
        }
        return mvc.perform(request);
    }

    /** 임의 상태의 토큰을 직접 심는다(만료·폐기는 서비스 발급 경로로는 만들 수 없다). */
    private String persistToken(User owner, Instant expiresAt, boolean revoked) {
        String raw = PersonalAccessTokenService.TOKEN_PREFIX + UUID.randomUUID();
        PersonalAccessToken token = new PersonalAccessToken(owner.getId(), "라벨",
                RefreshTokenService.sha256(raw), raw.substring(raw.length() - 4),
                List.of(PatScopes.WIKI_READ), Instant.now(), expiresAt);
        if (revoked) {
            token.revoke(Instant.now());
        }
        tokenRepository.save(token);
        return raw;
    }

    // ---------- 성공 ----------

    @Test
    void exchanges_active_token_for_a_short_lived_platform_jwt() throws Exception {
        String raw = tokenService.create(alice.getId(), "CI", 90, List.of(PatScopes.WIKI_READ)).rawToken();

        String response = exchange(raw, SECRET)
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        Map<?, ?> body = objectMapper.readValue(response, Map.class);
        assertThat(((Number) body.get("expiresInSeconds")).longValue()).isEqualTo(PAT_JWT_TTL);

        SignedJWT jwt = SignedJWT.parse((String) body.get("accessToken"));
        var claims = jwt.getJWTClaimsSet();
        assertThat(claims.getSubject()).isEqualTo(String.valueOf(alice.getId()));
        assertThat(claims.getStringClaim("provider")).isEqualTo("PAT");
        assertThat(claims.getStringClaim("email")).isEqualTo("alice@demo.com");
        assertThat(claims.getStringListClaim("roles")).containsExactly("USER", "ADMIN");
        // 게이트웨이 PatScopeWebFilter가 읽는 계약 — 이름은 scope, 값은 문자열 배열.
        assertThat(claims.getStringListClaim("scope")).containsExactly("wiki:read");
        assertThat(claims.getAudience()).containsExactly("platform-api");
        // 세션 AT(900s)이 아니라 PAT 전용 TTL로 서명됐는지 — exp-iat로 실측.
        long ttl = (claims.getExpirationTime().getTime() - claims.getIssueTime().getTime()) / 1000;
        assertThat(ttl).isEqualTo(PAT_JWT_TTL);
    }

    @Test
    void scope_claim_carries_exactly_the_tokens_scopes() throws Exception {
        String raw = tokenService.create(alice.getId(), "여러 스코프", 90,
                List.of(PatScopes.ADMIN, PatScopes.ALM_WRITE, PatScopes.WIKI_READ)).rawToken();

        String response = exchange(raw, SECRET).andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        Map<?, ?> body = objectMapper.readValue(response, Map.class);
        var claims = SignedJWT.parse((String) body.get("accessToken")).getJWTClaimsSet();

        // 사용자 롤(USER/ADMIN)과 스코프는 별개다 — 토큰에 준 것만 실린다.
        assertThat(claims.getStringListClaim("scope"))
                .containsExactly("admin", "alm:write", "wiki:read");
        assertThat(claims.getStringListClaim("roles")).containsExactly("USER", "ADMIN");
    }

    // ---------- 실패는 전부 같은 401 ----------

    @Test
    void unknown_expired_revoked_and_disabled_all_return_the_same_401() throws Exception {
        String unknown = PersonalAccessTokenService.TOKEN_PREFIX + UUID.randomUUID();
        String expired = persistToken(alice, Instant.now().minus(1, ChronoUnit.MINUTES), false);
        String revoked = persistToken(alice, Instant.now().plus(30, ChronoUnit.DAYS), true);

        User disabled = new User("kc-disabled-" + System.nanoTime());
        disabled.setRoles(List.of("USER"));
        disabled.setEnabled(false);
        disabled = userRepository.save(disabled);
        String ofDisabledUser = persistToken(disabled, Instant.now().plus(30, ChronoUnit.DAYS), false);

        for (String raw : List.of(unknown, expired, revoked, ofDisabledUser, "", "not-a-pat")) {
            exchange(raw, SECRET)
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.error").value("invalid_token"))
                    // 응답에 다른 필드가 붙으면 어느 실패인지 구분할 단서가 된다.
                    .andExpect(jsonPath("$.length()").value(1));
        }
    }

    @Test
    void expired_token_stays_rejected_and_is_not_touched() throws Exception {
        String expired = persistToken(alice, Instant.now().minus(1, ChronoUnit.MINUTES), false);

        exchange(expired, SECRET).andExpect(status().isUnauthorized());

        assertThat(tokenRepository.findByTokenHash(RefreshTokenService.sha256(expired)).orElseThrow()
                .getLastUsedAt()).isNull();
    }

    // ---------- 내부 시크릿 ----------

    @Test
    void wrong_or_missing_internal_secret_is_403() throws Exception {
        String raw = tokenService.create(alice.getId(), "CI", 90, List.of(PatScopes.WIKI_READ)).rawToken();

        exchange(raw, "wrong-secret").andExpect(status().isForbidden());
        exchange(raw, null).andExpect(status().isForbidden());

        // 시크릿을 못 넘긴 요청은 교환 자체가 일어나지 않았다.
        assertThat(tokenRepository.findByTokenHash(RefreshTokenService.sha256(raw)).orElseThrow()
                .getLastUsedAt()).isNull();
    }

    // ---------- last_used_at 스로틀 ----------

    @Test
    void last_used_at_updates_at_most_once_per_minute() throws Exception {
        String raw = tokenService.create(alice.getId(), "CI", 90, List.of(PatScopes.WIKI_READ)).rawToken();
        String hash = RefreshTokenService.sha256(raw);

        exchange(raw, SECRET).andExpect(status().isOk());
        Instant first = tokenRepository.findByTokenHash(hash).orElseThrow().getLastUsedAt();
        assertThat(first).isNotNull();

        // 곧바로 다시 교환 — 스로틀 창(60초) 안이라 갱신되지 않는다.
        exchange(raw, SECRET).andExpect(status().isOk());
        assertThat(tokenRepository.findByTokenHash(hash).orElseThrow().getLastUsedAt()).isEqualTo(first);

        // 마지막 사용 시각을 2분 전으로 되돌리면 다음 교환에서 갱신된다.
        PersonalAccessToken stale = tokenRepository.findByTokenHash(hash).orElseThrow();
        Instant backdated = Instant.now().minus(2, ChronoUnit.MINUTES);
        stale.setLastUsedAt(backdated);
        tokenRepository.save(stale);

        exchange(raw, SECRET).andExpect(status().isOk());
        assertThat(tokenRepository.findByTokenHash(hash).orElseThrow().getLastUsedAt()).isAfter(backdated);
    }
}
