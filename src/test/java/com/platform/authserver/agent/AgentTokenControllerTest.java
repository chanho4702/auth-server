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

    /**
     * 시크릿 미설정 — 별도 Spring 컨텍스트로 격리. {@code @Nested}의 {@code NestedTestConfiguration}
     * 기본값(INHERIT)이라 바깥 클래스의 {@code @TestPropertySource(internal-secret=test-internal-secret)}가
     * 상속되어 버린다 — 여기서 명시적으로 빈 문자열로 재선언(로컬 선언이 상속값을 덮어씀)해야
     * {@code !secret.isEmpty()} 가드가 실제로 커버된다(C2). 확인 방법: 그 가드를 지우고 이 테스트가
     * 실패하는지 봐야 한다 — 지운 채로 돌리면 실제로 FAIL함을 확인했다(수정 리포트 참고).
     */
    @Nested
    @SpringBootTest
    @ActiveProfiles("test")
    @Import(TestOAuth2ClientConfig.class)
    @TestPropertySource(properties = "platform.agent.internal-secret=")
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

            // 임의값 헤더 — 길이가 달라 MessageDigest.isEqual 자체가 이미 false. 이 케이스만으로는
            // "!secret.isEmpty()" 가드의 유무를 구분하지 못한다(가드를 지워도 여전히 403).
            nestedMvc.perform(post("/internal/service-tokens")
                            .header("X-Internal-Secret", "anything")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"userId\":" + agent.userId() + "}"))
                    .andExpect(status().isForbidden());

            // 빈 문자열 헤더 — 빈 시크릿과 값이 "일치"하므로 MessageDigest.isEqual("", "")는 true다.
            // "!secret.isEmpty()" 가드가 없으면 이 요청이 통과(200)해버린다 — 가드가 실제로 막는
            // 유일한 경로가 이것. 가드를 지우고 돌려서 이 assertion이 FAIL함을 확인했다(C2, 수정 리포트 참고).
            nestedMvc.perform(post("/internal/service-tokens")
                            .header("X-Internal-Secret", "")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"userId\":" + agent.userId() + "}"))
                    .andExpect(status().isForbidden());
        }
    }
}
