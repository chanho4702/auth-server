package com.platform.authserver.agent;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.platform.authserver.TestOAuth2ClientConfig;
import com.platform.authserver.user.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
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

/** {@code POST /internal/agents} — 시크릿 게이트와 {@code /api/auth/agents}와의 응답 동일성. */
@SpringBootTest
@ActiveProfiles("test")
@Import(TestOAuth2ClientConfig.class)
@TestPropertySource(properties = "platform.agent.internal-secret=test-internal-secret")
class InternalAgentRegistrationTest {

    private static final String SECRET = "test-internal-secret";

    @Autowired WebApplicationContext context;
    @Autowired UserRepository userRepository;
    MockMvc mvc;
    final ObjectMapper objectMapper = new ObjectMapper();

    @SuppressWarnings("unchecked")
    private Map<String, Object> read(String json) throws Exception {
        return objectMapper.readValue(json, Map.class);
    }

    @BeforeEach
    void setup() {
        mvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
        userRepository.deleteAll();
    }

    @Test
    void creates_agent_idempotently_with_secret() throws Exception {
        String body = "{\"slug\":\"jiho\",\"name\":\"지호\",\"email\":\"jiho@agents.local\"}";

        Map<String, Object> first = postInternal(body);
        assertThat(first).containsOnlyKeys("userId", "slug", "created");
        assertThat(((Number) first.get("userId")).longValue()).isGreaterThan(0);
        assertThat(first.get("slug")).isEqualTo("jiho");
        assertThat(first.get("created")).isEqualTo(true);

        Map<String, Object> second = postInternal(body);
        assertThat(second.get("userId")).isEqualTo(first.get("userId"));
        assertThat(second.get("created")).isEqualTo(false);
        assertThat(userRepository.count()).isEqualTo(1);
    }

    /** 같은 사용자를 두 경로가 공유한다 — 어느 쪽으로 먼저 만들든 다른 쪽은 created=false로 같은 userId. */
    @Test
    void same_shape_and_same_user_as_admin_endpoint() throws Exception {
        String body = "{\"slug\":\"shared\",\"name\":\"공유\"}";

        String adminResponse = mvc.perform(post("/api/auth/agents")
                        .with(jwt().jwt(j -> j.subject("1").claim("roles", List.of("ADMIN")))
                                .authorities(new SimpleGrantedAuthority("ROLE_ADMIN")))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        Map<String, Object> viaAdmin = read(adminResponse);

        Map<String, Object> viaInternal = postInternal(body);

        assertThat(viaInternal.keySet()).isEqualTo(viaAdmin.keySet());
        assertThat(viaInternal.get("userId")).isEqualTo(viaAdmin.get("userId"));
        assertThat(viaInternal.get("slug")).isEqualTo(viaAdmin.get("slug"));
        assertThat(viaInternal.get("created")).isEqualTo(false);
    }

    @Test
    void bad_slug_rejected_same_as_admin_endpoint() throws Exception {
        mvc.perform(post("/internal/agents")
                        .header("X-Internal-Secret", SECRET)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"slug\":\"Jiho!\",\"name\":\"지호\"}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void wrong_or_missing_secret_forbidden_and_nothing_created() throws Exception {
        String body = "{\"slug\":\"jiho\",\"name\":\"지호\"}";

        mvc.perform(post("/internal/agents")
                        .header("X-Internal-Secret", "wrong-secret")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isForbidden());

        mvc.perform(post("/internal/agents")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isForbidden());

        assertThat(userRepository.count()).isZero();
    }

    /** 관리자 JWT만으로는 내부 경로를 통과하지 못한다 — 이 경로의 인증 수단은 시크릿 하나다. */
    @Test
    void admin_jwt_without_secret_forbidden() throws Exception {
        mvc.perform(post("/internal/agents")
                        .with(jwt().jwt(j -> j.subject("1").claim("roles", List.of("ADMIN")))
                                .authorities(new SimpleGrantedAuthority("ROLE_ADMIN")))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"slug\":\"jiho\",\"name\":\"지호\"}"))
                .andExpect(status().isForbidden());

        assertThat(userRepository.count()).isZero();
    }

    private Map<String, Object> postInternal(String body) throws Exception {
        String response = mvc.perform(post("/internal/agents")
                        .header("X-Internal-Secret", SECRET)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        return read(response);
    }

    /** 바깥 클래스의 시크릿이 상속되므로 빈 문자열로 재선언해야 미설정 상태가 된다. */
    @Nested
    @SpringBootTest
    @ActiveProfiles("test")
    @Import(TestOAuth2ClientConfig.class)
    @TestPropertySource(properties = "platform.agent.internal-secret=")
    class WhenSecretNotConfigured {

        @Autowired WebApplicationContext nestedContext;
        @Autowired UserRepository nestedUserRepository;
        MockMvc nestedMvc;

        @BeforeEach
        void setup() {
            nestedMvc = MockMvcBuilders.webAppContextSetup(nestedContext).apply(springSecurity()).build();
            nestedUserRepository.deleteAll();
        }

        @Test
        void fail_closed_even_with_empty_header() throws Exception {
            for (String header : new String[] {"anything", ""}) {
                nestedMvc.perform(post("/internal/agents")
                                .header("X-Internal-Secret", header)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"slug\":\"jiho\",\"name\":\"지호\"}"))
                        .andExpect(status().isForbidden());
            }
            assertThat(nestedUserRepository.count()).isZero();
        }
    }
}
