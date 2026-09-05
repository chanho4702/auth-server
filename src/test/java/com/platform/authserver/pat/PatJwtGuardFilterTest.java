package com.platform.authserver.pat;

import com.platform.authserver.TestOAuth2ClientConfig;
import com.platform.authserver.jwt.JwtService;
import com.platform.authserver.user.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * {@link PatJwtGuardFilter} — PAT 교환 JWT의 자기 증식 경로 차단.
 *
 * <p>전부 {@link JwtService}로 서명한 <b>진짜 토큰</b>을 {@code Authorization} 헤더로 보낸다.
 * {@code jwt()} 포스트프로세서로 권한을 주입하면 실제 디코더·컨버터·필터 순서를 건너뛰어,
 * "운영에서도 정말 막히는가"를 증명하지 못하기 때문이다.
 */
@SpringBootTest
@ActiveProfiles("test")
@Import(TestOAuth2ClientConfig.class)
class PatJwtGuardFilterTest {

    @Autowired WebApplicationContext context;
    @Autowired JwtService jwtService;
    @Autowired UserRepository userRepository;
    @Autowired PersonalAccessTokenRepository tokenRepository;

    MockMvc mvc;

    @BeforeEach
    void setup() {
        mvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
        tokenRepository.deleteAll();
        userRepository.deleteAll();
    }

    /** PAT 교환으로 나온 JWT. 롤은 주인 것을 그대로 물려받으므로 ADMIN일 수 있다. */
    private String patJwt(List<String> roles) {
        return jwtService.issueAccessToken(1L, "admin@demo.com", "관리자", roles, "PAT");
    }

    /** 사람이 브라우저로 로그인해 받은 세션 JWT. */
    private String sessionJwt(List<String> roles) {
        return jwtService.issueAccessToken(1L, "admin@demo.com", "관리자", roles, "KEYCLOAK");
    }

    // ---------- /api/auth/agents ----------

    /**
     * 핵심 우회 시나리오: 관리자가 만든 PAT는 ADMIN 롤을 가진다. 그 토큰으로 에이전트 페르소나를
     * 만들 수 있으면, 그 페르소나의 서비스 토큰({@code /internal/service-tokens})까지 이어져
     * 토큰이 토큰을 낳는 고리가 생긴다.
     */
    @Test
    void pat_jwt_with_admin_role_cannot_create_agents() throws Exception {
        mvc.perform(post("/api/auth/agents")
                        .header("Authorization", "Bearer " + patJwt(List.of("ADMIN")))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"slug\":\"sneaky\",\"name\":\"우회\"}"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("pat_cannot_manage_tokens"));

        // 상태 코드만 맞고 실제로는 만들어졌다면 의미가 없다.
        assertThat(userRepository.count()).isZero();
    }

    /** 하위 경로도 같은 프리픽스로 덮인다 — 새 엔드포인트가 생겨도 자동으로 막힌다. */
    @Test
    void pat_jwt_is_blocked_on_agents_sub_paths_too() throws Exception {
        mvc.perform(post("/api/auth/agents/anything")
                        .header("Authorization", "Bearer " + patJwt(List.of("ADMIN")))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("pat_cannot_manage_tokens"));
    }

    /** 기존 동작 보존 — 사람이 로그인한 ADMIN 세션은 그대로 통과해야 한다. */
    @Test
    void session_admin_jwt_still_creates_agents() throws Exception {
        mvc.perform(post("/api/auth/agents")
                        .header("Authorization", "Bearer " + sessionJwt(List.of("ADMIN")))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"slug\":\"jiho\",\"name\":\"지호\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.slug").value("jiho"))
                .andExpect(jsonPath("$.created").value(true));

        assertThat(userRepository.count()).isEqualTo(1);
    }

    /** ADMIN이 아닌 세션은 종전대로 ADMIN 게이트에서 막힌다(PAT 코드가 아니라 평범한 403). */
    @Test
    void non_admin_session_jwt_is_still_plain_forbidden() throws Exception {
        mvc.perform(post("/api/auth/agents")
                        .header("Authorization", "Bearer " + sessionJwt(List.of("USER")))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"slug\":\"jiho\",\"name\":\"지호\"}"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").doesNotExist());
    }

    // ---------- /api/auth/tokens ----------

    @Test
    void pat_jwt_cannot_manage_tokens_on_any_verb() throws Exception {
        String pat = patJwt(List.of("USER"));

        mvc.perform(get("/api/auth/tokens").header("Authorization", "Bearer " + pat))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("pat_cannot_manage_tokens"));

        mvc.perform(post("/api/auth/tokens")
                        .header("Authorization", "Bearer " + pat)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"label\":\"자기복제\"}"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("pat_cannot_manage_tokens"));

        mvc.perform(delete("/api/auth/tokens/" + UUID.randomUUID())
                        .header("Authorization", "Bearer " + pat))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("pat_cannot_manage_tokens"));

        assertThat(tokenRepository.count()).isZero();
    }

    // ---------- 정당한 PAT 사용은 막지 않는다 ----------

    /**
     * 가드가 너무 넓게 걸리면 PAT 자체가 쓸모없어진다. {@code /api/me}는 PAT의 주 용도이므로
     * 반드시 통과해야 한다 — 이 테스트가 가드 범위의 상한선이다.
     */
    @Test
    void pat_jwt_still_works_on_me() throws Exception {
        mvc.perform(get("/api/me").header("Authorization", "Bearer " + patJwt(List.of("USER"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.provider").value("PAT"))
                .andExpect(jsonPath("$.sub").value("1"));
    }
}
