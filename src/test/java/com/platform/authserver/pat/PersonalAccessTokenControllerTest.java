package com.platform.authserver.pat;

import com.fasterxml.jackson.databind.ObjectMapper;
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
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** `/api/auth/tokens` 관리 API — 발급·목록·폐기·검증·PAT-JWT 차단·익명 차단. */
@SpringBootTest
@ActiveProfiles("test")
@Import(TestOAuth2ClientConfig.class)
class PersonalAccessTokenControllerTest {

    @Autowired WebApplicationContext context;
    @Autowired PersonalAccessTokenRepository tokenRepository;
    @Autowired UserRepository userRepository;
    @Autowired PersonalAccessTokenService tokenService;

    MockMvc mvc;
    final ObjectMapper objectMapper = new ObjectMapper();

    User alice;
    User bob;

    @BeforeEach
    void setup() {
        mvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
        tokenRepository.deleteAll();
        userRepository.deleteAll();
        alice = newUser("kc-alice");
        bob = newUser("kc-bob");
    }

    private User newUser(String sub) {
        User u = new User(sub + "-" + System.nanoTime());
        u.setRoles(List.of("USER"));
        u.setProvider("KEYCLOAK");
        return userRepository.save(u);
    }

    /** 로그인 세션 JWT(provider=KEYCLOAK). */
    private RequestPostProcessor as(User user) {
        return jwt().jwt(j -> j.subject(String.valueOf(user.getId()))
                .claim("provider", "KEYCLOAK")
                .claim("roles", List.of("USER")));
    }

    /** PAT 교환으로 받은 JWT(provider=PAT) — 관리 API를 쓸 수 없어야 한다. */
    private RequestPostProcessor asPatJwt(User user) {
        return jwt().jwt(j -> j.subject(String.valueOf(user.getId()))
                .claim("provider", "PAT")
                .claim("roles", List.of("USER")));
    }

    private PersonalAccessToken persistToken(User owner, String label, Instant createdAt, Instant expiresAt) {
        String raw = PersonalAccessTokenService.TOKEN_PREFIX + UUID.randomUUID();
        return tokenRepository.save(new PersonalAccessToken(owner.getId(), label,
                RefreshTokenService.sha256(raw), raw.substring(raw.length() - 4),
                List.of(PatScopes.WIKI_READ), createdAt, expiresAt));
    }

    // ---------- 발급 ----------

    @Test
    void create_returns_raw_token_once_and_stores_only_hash() throws Exception {
        String response = mvc.perform(post("/api/auth/tokens").with(as(alice))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"label\":\"CI 배포\",\"expiresInDays\":30,\"scopes\":[\"wiki:read\"]}"))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.label").value("CI 배포"))
                .andReturn().getResponse().getContentAsString();

        Map<?, ?> body = objectMapper.readValue(response, Map.class);
        String raw = (String) body.get("token");
        assertThat(raw).startsWith(PersonalAccessTokenService.TOKEN_PREFIX);
        // chanho_pat_(11) + base64url(32바이트, 패딩 없음, 43자)
        assertThat(raw).hasSize(11 + 43);
        assertThat(body.get("hint")).isEqualTo(raw.substring(raw.length() - 4));

        PersonalAccessToken stored = tokenRepository.findById(UUID.fromString((String) body.get("id"))).orElseThrow();
        assertThat(stored.getTokenHash()).isEqualTo(RefreshTokenService.sha256(raw));
        assertThat(stored.getTokenHash()).doesNotContain(raw);
        assertThat(stored.getUserId()).isEqualTo(alice.getId());
        assertThat(stored.getExpiresAt()).isCloseTo(Instant.now().plus(30, ChronoUnit.DAYS),
                org.assertj.core.api.Assertions.within(1, ChronoUnit.MINUTES));
    }

    @Test
    void create_defaults_to_90_days_and_never_repeats_the_raw_token() throws Exception {
        mvc.perform(post("/api/auth/tokens").with(as(alice))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"label\":\"스크립트\",\"scopes\":[\"wiki:read\"]}"))
                .andExpect(status().isCreated());

        PersonalAccessToken stored = tokenRepository.findAll().get(0);
        assertThat(stored.getExpiresAt()).isCloseTo(Instant.now().plus(90, ChronoUnit.DAYS),
                org.assertj.core.api.Assertions.within(1, ChronoUnit.MINUTES));

        // 목록 응답 어디에도 원문이 없다.
        mvc.perform(get("/api/auth/tokens").with(as(alice)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].token").doesNotExist())
                .andExpect(jsonPath("$[0].hint").value(stored.getTokenHint()));
    }

    @Test
    void create_rejects_missing_blank_and_overlong_label() throws Exception {
        for (String body : List.of("{}",
                "{\"label\":\"   \",\"scopes\":[\"wiki:read\"]}",
                "{\"label\":\"" + "가".repeat(101) + "\",\"scopes\":[\"wiki:read\"]}")) {
            mvc.perform(post("/api/auth/tokens").with(as(alice))
                            .contentType(MediaType.APPLICATION_JSON).content(body))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.error").value("label_required"));
        }
        assertThat(tokenRepository.count()).isZero();
    }

    @Test
    void create_rejects_expiry_outside_1_to_365() throws Exception {
        for (int days : List.of(0, -1, 366)) {
            mvc.perform(post("/api/auth/tokens").with(as(alice))
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"label\":\"x\",\"scopes\":[\"wiki:read\"],\"expiresInDays\":" + days + "}"))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.error").value("invalid_expiry"));
        }
        assertThat(tokenRepository.count()).isZero();
    }

    @Test
    void create_rejects_26th_active_token_with_409() throws Exception {
        for (int i = 0; i < PersonalAccessTokenService.MAX_ACTIVE_TOKENS; i++) {
            tokenService.create(alice.getId(), "t" + i, 90, List.of(PatScopes.WIKI_READ));
        }

        mvc.perform(post("/api/auth/tokens").with(as(alice))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"label\":\"26번째\",\"scopes\":[\"wiki:read\"]}"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.error").value("token_limit"));

        // 폐기·만료된 토큰은 한도에 안 들어간다 — 하나 폐기하면 다시 발급된다.
        PersonalAccessToken victim = tokenRepository.findByUserIdOrderByCreatedAtDesc(alice.getId()).get(0);
        tokenService.revoke(alice.getId(), victim.getId());
        mvc.perform(post("/api/auth/tokens").with(as(alice))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"label\":\"재발급\",\"scopes\":[\"wiki:read\"]}"))
                .andExpect(status().isCreated());
    }

    // ---------- 스코프 ----------

    @Test
    void create_requires_at_least_one_scope() throws Exception {
        for (String body : List.of(
                "{\"label\":\"스코프 없음\"}",
                "{\"label\":\"스코프 없음\",\"scopes\":null}",
                "{\"label\":\"스코프 없음\",\"scopes\":[]}",
                "{\"label\":\"스코프 없음\",\"scopes\":[\"  \"]}")) {
            mvc.perform(post("/api/auth/tokens").with(as(alice))
                            .contentType(MediaType.APPLICATION_JSON).content(body))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.error").value("scopes_required"));
        }
        assertThat(tokenRepository.count()).isZero();
    }

    @Test
    void create_rejects_unknown_scopes() throws Exception {
        for (String body : List.of(
                "{\"label\":\"오타\",\"scopes\":[\"wiki:delete\"]}",
                "{\"label\":\"대소문자\",\"scopes\":[\"WIKI:READ\"]}",
                "{\"label\":\"섞임\",\"scopes\":[\"wiki:read\",\"board:read\"]}")) {
            mvc.perform(post("/api/auth/tokens").with(as(alice))
                            .contentType(MediaType.APPLICATION_JSON).content(body))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.error").value("scopes_invalid"));
        }
        assertThat(tokenRepository.count()).isZero();
    }

    @Test
    void create_normalizes_scopes_and_echoes_them_in_the_response() throws Exception {
        String response = mvc.perform(post("/api/auth/tokens").with(as(alice))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"label\":\"정규화\",\"scopes\":[\" wiki:write \",\"admin\",\"wiki:write\",\"alm:read\"]}"))
                .andExpect(status().isCreated())
                // 중복 제거 + 사전순 정렬
                .andExpect(jsonPath("$.scopes", contains("admin", "alm:read", "wiki:write")))
                .andReturn().getResponse().getContentAsString();

        Map<?, ?> body = objectMapper.readValue(response, Map.class);
        PersonalAccessToken stored = tokenRepository.findById(UUID.fromString((String) body.get("id"))).orElseThrow();
        assertThat(stored.getScopes()).containsExactly("admin", "alm:read", "wiki:write");
    }

    @Test
    void list_exposes_scopes() throws Exception {
        tokenService.create(alice.getId(), "목록", 30, List.of(PatScopes.ORG_WRITE, PatScopes.WIKI_READ));

        mvc.perform(get("/api/auth/tokens").with(as(alice)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].scopes", contains("org:write", "wiki:read")))
                .andExpect(jsonPath("$[0].token").doesNotExist());
    }

    // ---------- 목록 ----------

    @Test
    void list_returns_only_own_tokens_newest_first() throws Exception {
        Instant now = Instant.now();
        persistToken(alice, "오래된", now.minus(2, ChronoUnit.DAYS), now.plus(30, ChronoUnit.DAYS));
        persistToken(alice, "최신", now.minus(1, ChronoUnit.HOURS), now.plus(30, ChronoUnit.DAYS));
        persistToken(bob, "밥의 것", now, now.plus(30, ChronoUnit.DAYS));

        mvc.perform(get("/api/auth/tokens").with(as(alice)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(2))
                .andExpect(jsonPath("$[0].label").value("최신"))
                .andExpect(jsonPath("$[1].label").value("오래된"));

        mvc.perform(get("/api/auth/tokens").with(as(bob)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(1))
                .andExpect(jsonPath("$[0].label").value("밥의 것"));
    }

    // ---------- 폐기 ----------

    @Test
    void revoke_is_idempotent_and_keeps_the_row() throws Exception {
        Instant now = Instant.now();
        PersonalAccessToken token = persistToken(alice, "폐기 대상", now, now.plus(30, ChronoUnit.DAYS));

        mvc.perform(delete("/api/auth/tokens/" + token.getId()).with(as(alice)))
                .andExpect(status().isNoContent());
        Instant firstRevokedAt = tokenRepository.findById(token.getId()).orElseThrow().getRevokedAt();
        assertThat(firstRevokedAt).isNotNull();

        mvc.perform(delete("/api/auth/tokens/" + token.getId()).with(as(alice)))
                .andExpect(status().isNoContent());
        // 감사 기록이므로 행도 최초 폐기 시각도 그대로 남는다.
        assertThat(tokenRepository.findById(token.getId()).orElseThrow().getRevokedAt()).isEqualTo(firstRevokedAt);
    }

    @Test
    void revoke_of_someone_elses_token_is_404_and_leaves_it_alone() throws Exception {
        Instant now = Instant.now();
        PersonalAccessToken bobs = persistToken(bob, "밥의 것", now, now.plus(30, ChronoUnit.DAYS));

        mvc.perform(delete("/api/auth/tokens/" + bobs.getId()).with(as(alice)))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").value("not_found"));

        assertThat(tokenRepository.findById(bobs.getId()).orElseThrow().getRevokedAt()).isNull();
    }

    @Test
    void revoke_of_unknown_or_malformed_id_is_404() throws Exception {
        mvc.perform(delete("/api/auth/tokens/" + UUID.randomUUID()).with(as(alice)))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").value("not_found"));

        mvc.perform(delete("/api/auth/tokens/not-a-uuid").with(as(alice)))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").value("not_found"));
    }

    // ---------- PAT-JWT 차단 ----------

    @Test
    void pat_issued_jwt_cannot_manage_tokens() throws Exception {
        Instant now = Instant.now();
        PersonalAccessToken token = persistToken(alice, "기존", now, now.plus(30, ChronoUnit.DAYS));

        mvc.perform(get("/api/auth/tokens").with(asPatJwt(alice)))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("pat_cannot_manage_tokens"));

        mvc.perform(post("/api/auth/tokens").with(asPatJwt(alice))
                        .contentType(MediaType.APPLICATION_JSON).content("{\"label\":\"자기복제\"}"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("pat_cannot_manage_tokens"));

        mvc.perform(delete("/api/auth/tokens/" + token.getId()).with(asPatJwt(alice)))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("pat_cannot_manage_tokens"));

        // 토큰이 늘지도 폐기되지도 않았다.
        assertThat(tokenRepository.count()).isEqualTo(1);
        assertThat(tokenRepository.findById(token.getId()).orElseThrow().getRevokedAt()).isNull();
    }

    // ---------- 익명 차단(permitAll 함정 회귀) ----------

    /**
     * {@code /api/auth/**}는 webChain에서 permitAll이므로, apiChain의 securityMatcher에
     * {@code /api/auth/tokens/**}가 빠지면 이 경로가 익명에게 열린다. 401이 아니라 200/500이
     * 나오면 그 회귀가 일어난 것이다.
     */
    @Test
    void anonymous_list_is_unauthorized() throws Exception {
        mvc.perform(get("/api/auth/tokens")).andExpect(status().isUnauthorized());
    }

    @Test
    void anonymous_create_and_revoke_are_unauthorized() throws Exception {
        mvc.perform(post("/api/auth/tokens")
                        .contentType(MediaType.APPLICATION_JSON).content("{\"label\":\"익명\"}"))
                .andExpect(status().isUnauthorized());

        mvc.perform(delete("/api/auth/tokens/" + UUID.randomUUID()))
                .andExpect(status().isUnauthorized());

        assertThat(tokenRepository.count()).isZero();
    }
}
