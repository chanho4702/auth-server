package com.platform.authserver.agent;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.platform.authserver.TestOAuth2ClientConfig;
import com.platform.authserver.jwt.JwtService;
import com.platform.authserver.user.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@ActiveProfiles("test")
@Import(TestOAuth2ClientConfig.class)
class AgentAdminControllerTest {

    @Autowired WebApplicationContext context;
    @Autowired UserRepository userRepository;
    @Autowired JwtService jwtService;
    MockMvc mvc;
    final ObjectMapper objectMapper = new ObjectMapper();

    @BeforeEach
    void setup() {
        mvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
        userRepository.deleteAll();
    }

    @Test
    void admin_creates_agent_user_idempotently() throws Exception {
        String body = "{\"slug\":\"jiho\",\"name\":\"지호\"}";

        String firstResponse = mvc.perform(post("/api/auth/agents")
                        .with(jwt().jwt(j -> j.subject("1").claim("roles", List.of("ADMIN")))
                                .authorities(new SimpleGrantedAuthority("ROLE_ADMIN")))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        Map<?, ?> first = objectMapper.readValue(firstResponse, Map.class);
        assertThat(((Number) first.get("userId")).longValue()).isGreaterThan(0);
        assertThat(first.get("slug")).isEqualTo("jiho");
        assertThat(first.get("created")).isEqualTo(true);
        assertThat(userRepository.count()).isEqualTo(1);

        String secondResponse = mvc.perform(post("/api/auth/agents")
                        .with(jwt().jwt(j -> j.subject("1").claim("roles", List.of("ADMIN")))
                                .authorities(new SimpleGrantedAuthority("ROLE_ADMIN")))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        Map<?, ?> second = objectMapper.readValue(secondResponse, Map.class);
        assertThat(second.get("userId")).isEqualTo(first.get("userId"));
        assertThat(second.get("created")).isEqualTo(false);
        assertThat(userRepository.count()).isEqualTo(1);
    }

    @Test
    void non_admin_forbidden() throws Exception {
        mvc.perform(post("/api/auth/agents")
                        .with(jwt().jwt(j -> j.subject("1").claim("roles", List.of("USER")))
                                .authorities(new SimpleGrantedAuthority("ROLE_USER")))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"slug\":\"jiho\",\"name\":\"지호\"}"))
                .andExpect(status().isForbidden());
    }

    /**
     * 다른 테스트들은 전부 {@code jwt().authorities(...)}로 권한을 직접 주입한다 — 앱의 실제
     * roles→ROLE_* 컨버터 경로(SecurityConfig.jwtAuthenticationConverter)는 아무도 안 거친다.
     * 이 테스트는 진짜 JwtService로 서명한 토큰을 Authorization 헤더로 보내 실제 JwtDecoder +
     * 컨버터를 end-to-end로 태운다(I2).
     */
    @Test
    void real_admin_token_authorizes_via_roles_converter() throws Exception {
        String adminToken = jwtService.issueAccessToken(999L, "admin@agents.local", "Admin", List.of("ADMIN"), "TEST");

        mvc.perform(post("/api/auth/agents")
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"slug\":\"realtoken\",\"name\":\"Real\"}"))
                .andExpect(status().isOk());
    }

    @Test
    void real_user_token_forbidden_via_roles_converter() throws Exception {
        String userToken = jwtService.issueAccessToken(998L, "user@agents.local", "User", List.of("USER"), "TEST");

        mvc.perform(post("/api/auth/agents")
                        .header("Authorization", "Bearer " + userToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"slug\":\"realtoken2\",\"name\":\"Real\"}"))
                .andExpect(status().isForbidden());
    }

    /**
     * I1 회귀 가드. 매처가 리터럴 {@code /api/auth/agents}만이었다면 이 서브패스는 apiChain에
     * 안 걸리고 webChain의 {@code /api/auth/**} permitAll로 떨어져 익명 요청이 (핸들러가 없어)
     * 404로 통과해버린다 — 겉보기엔 "막힌 것처럼" 보이지만 실제로는 인가 검사를 아예 안 거친
     * 것. {@code /api/auth/agents/**}가 apiChain에 있으면 인가 검사가 먼저 걸려 401이 난다.
     */
    @Test
    void agents_sub_path_requires_authentication_not_permitAll_fallback() throws Exception {
        mvc.perform(post("/api/auth/agents/some-sub-path")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void bad_slug_rejected() throws Exception {
        mvc.perform(post("/api/auth/agents")
                        .with(jwt().jwt(j -> j.subject("1").claim("roles", List.of("ADMIN")))
                                .authorities(new SimpleGrantedAuthority("ROLE_ADMIN")))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"slug\":\"Jiho!\",\"name\":\"지호\"}"))
                .andExpect(status().isBadRequest());
    }
}
