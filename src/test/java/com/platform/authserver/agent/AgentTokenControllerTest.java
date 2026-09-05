package com.platform.authserver.agent;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import com.platform.authserver.TestOAuth2ClientConfig;
import com.platform.authserver.user.User;
import com.platform.authserver.user.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
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

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 시크릿이 설정된 컨텍스트(클래스 레벨 {@link TestPropertySource})에서 3건, 시크릿 미설정
 * 컨텍스트({@link WhenSecretNotConfigured}, 별도 Spring 컨텍스트)에서 1건 — 총 4건.
 */
@SpringBootTest
@ActiveProfiles("test")
@Import(TestOAuth2ClientConfig.class)
@TestPropertySource(properties = "platform.agent.internal-secret=test-internal-secret")
class AgentTokenControllerTest {

    @Autowired WebApplicationContext context;
    @Autowired UserRepository userRepository;
    @Autowired AgentUserService agentUserService;
    MockMvc mvc;
    final ObjectMapper objectMapper = new ObjectMapper();

    @BeforeEach
    void setup() {
        mvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
        userRepository.deleteAll();
    }

    @Test
    void mints_token_for_agent_user_with_secret() throws Exception {
        AgentUserService.AgentResult agent = agentUserService.createOrGet("jiho", "지호", "jiho@agents.local");

        String response = mvc.perform(post("/internal/service-tokens")
                        .header("X-Internal-Secret", "test-internal-secret")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"userId\":" + agent.userId() + "}"))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        Map<?, ?> body = objectMapper.readValue(response, Map.class);
        assertThat(((Number) body.get("expiresInSeconds")).longValue()).isEqualTo(900L);
        String accessToken = (String) body.get("accessToken");

        SignedJWT jwt = SignedJWT.parse(accessToken);
        assertThat(jwt.getJWTClaimsSet().getSubject()).isEqualTo(String.valueOf(agent.userId()));
        assertThat(jwt.getJWTClaimsSet().getAudience()).containsExactly("platform-api");
        assertThat(jwt.getJWTClaimsSet().getStringClaim("provider")).isEqualTo("AGENT");
    }

    @Test
    void refuses_human_user() throws Exception {
        User human = userRepository.save(new User("google-sub-1"));

        mvc.perform(post("/internal/service-tokens")
                        .header("X-Internal-Secret", "test-internal-secret")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"userId\":" + human.getId() + "}"))
                .andExpect(status().isForbidden());
    }

    @Test
    void refuses_wrong_or_missing_secret() throws Exception {
        AgentUserService.AgentResult agent = agentUserService.createOrGet("jiho2", "지호2", null);

        mvc.perform(post("/internal/service-tokens")
                        .header("X-Internal-Secret", "wrong-secret")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"userId\":" + agent.userId() + "}"))
                .andExpect(status().isForbidden());

        mvc.perform(post("/internal/service-tokens")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"userId\":" + agent.userId() + "}"))
                .andExpect(status().isForbidden());
    }

    /** 시크릿 미설정(기본 application.yml의 빈 문자열 기본값) — 별도 컨텍스트로 격리. */
    @Nested
    @SpringBootTest
    @ActiveProfiles("test")
    @Import(TestOAuth2ClientConfig.class)
    class WhenSecretNotConfigured {

        @Autowired WebApplicationContext nestedContext;
        @Autowired UserRepository nestedUserRepository;
        @Autowired AgentUserService nestedAgentUserService;
        MockMvc nestedMvc;

        @BeforeEach
        void setup() {
            nestedMvc = MockMvcBuilders.webAppContextSetup(nestedContext).apply(springSecurity()).build();
            nestedUserRepository.deleteAll();
        }

        @Test
        void disabled_when_secret_env_empty() throws Exception {
            AgentUserService.AgentResult agent = nestedAgentUserService.createOrGet("jiho3", "지호3", null);

            nestedMvc.perform(post("/internal/service-tokens")
                            .header("X-Internal-Secret", "anything")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"userId\":" + agent.userId() + "}"))
                    .andExpect(status().isForbidden());
        }
    }
}
