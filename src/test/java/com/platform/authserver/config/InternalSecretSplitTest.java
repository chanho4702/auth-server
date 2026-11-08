package com.platform.authserver.config;

import com.platform.authserver.TestOAuth2ClientConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.core.env.Environment;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;

/**
 * N5 — 내부 비밀 용도별 분리. 인바운드 {@code /internal/**}는 경로별 허용 토큰 집합을 따로 본다:
 * <ul>
 *   <li>PAT 교환({@code /internal/pat/**}, 게이트웨이) ← {@code AUTH_PAT_EXCHANGE_SECRET}</li>
 *   <li>에이전트 관리({@code /internal/agents}, {@code /internal/service-tokens}, agent-service) ← {@code AUTH_AGENT_ADMIN_SECRET}</li>
 *   <li>계정 동기화({@code /internal/users/**}, org-service, {@code X-Internal-Token}) ← {@code AUTH_ACCOUNT_SYNC_TOKEN}</li>
 * </ul>
 * 새 변수가 비면 옛 변수({@code AGENT_INTERNAL_SECRET}·{@code ORG_INTERNAL_TOKEN})로 폴백한다 — 값을 넣기 전까지 동작 불변.
 *
 * <p>통과 판정은 "게이트의 403이 아니다"(컨트롤러까지 갔다)로 본다 — 본문이 엉터리라 400/401이 나도 게이트는 통과한 것이다.
 */
class InternalSecretSplitTest {

    static final String SECRET_REJECT = "내부 시크릿이 유효하지 않습니다";
    static final String TOKEN_REJECT = "내부 API 토큰이 유효하지 않습니다";

    @SpringBootTest
    @ActiveProfiles("test")
    @Import(TestOAuth2ClientConfig.class)
    abstract static class Base {
        @Autowired WebApplicationContext context;
        @Autowired Environment env;
        MockMvc mvc;

        @BeforeEach
        void setupMvc() {
            mvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
        }

        MvcResult call(MockHttpServletRequestBuilder req, String header, String value) throws Exception {
            if (header != null) req.header(header, value);
            return mvc.perform(req.contentType(MediaType.APPLICATION_JSON).content("{}")).andReturn();
        }

        MvcResult patExchange(String secret) throws Exception {
            return call(post("/internal/pat/exchange"), "X-Internal-Secret", secret);
        }

        MvcResult patStats(String secret) throws Exception {
            return call(get("/internal/pat/stats"), "X-Internal-Secret", secret);
        }

        MvcResult agents(String secret) throws Exception {
            return call(post("/internal/agents"), "X-Internal-Secret", secret);
        }

        MvcResult serviceTokens(String secret) throws Exception {
            return call(post("/internal/service-tokens"), "X-Internal-Secret", secret);
        }

        MvcResult userStatus(String token) throws Exception {
            return call(put("/internal/users/1/status"), "X-Internal-Token", token);
        }

        static void assertPassed(MvcResult r) {
            assertThat(r.getResponse().getStatus()).as("게이트 통과(컨트롤러 도달)").isNotEqualTo(403);
        }

        static void assertRejected(MvcResult r, String message) throws Exception {
            assertThat(r.getResponse().getStatus()).isEqualTo(403);
            assertThat(r.getResponse().getContentAsString(StandardCharsets.UTF_8)).contains(message);
        }
    }

    /** 새 변수를 모두 넣고 옛 변수에도 다른 값을 둔다 — 경로마다 자기 값만 통과, 옛 값은 어디서도 안 열린다. */
    @Nested
    @TestPropertySource(properties = {
            "AUTH_PAT_EXCHANGE_SECRET=pat-secret",
            "AUTH_AGENT_ADMIN_SECRET=agent-secret",
            "AUTH_ACCOUNT_SYNC_TOKEN=sync-token",
            "ORG_IDENTITY_TOKEN=identity-token",
            "AGENT_INTERNAL_SECRET=legacy-secret",
            "ORG_INTERNAL_TOKEN=legacy-token"})
    class Split extends Base {

        @Test
        void pat_경로는_PAT_교환_비밀만_통과한다() throws Exception {
            assertPassed(patExchange("pat-secret"));
            assertPassed(patStats("pat-secret"));
            assertRejected(patExchange("agent-secret"), SECRET_REJECT);
            assertRejected(patStats("agent-secret"), SECRET_REJECT);
            assertRejected(patExchange("legacy-secret"), SECRET_REJECT);
            assertRejected(patExchange("sync-token"), SECRET_REJECT);
        }

        @Test
        void 에이전트_관리_경로는_에이전트_관리_비밀만_통과한다() throws Exception {
            assertPassed(agents("agent-secret"));
            assertPassed(serviceTokens("agent-secret"));
            assertRejected(agents("pat-secret"), SECRET_REJECT);
            assertRejected(serviceTokens("pat-secret"), SECRET_REJECT);
            assertRejected(serviceTokens("legacy-secret"), SECRET_REJECT);
        }

        @Test
        void 계정_동기화_경로는_계정_동기화_토큰만_통과한다() throws Exception {
            assertPassed(userStatus("sync-token"));
            assertRejected(userStatus("identity-token"), TOKEN_REJECT);
            assertRejected(userStatus("legacy-token"), TOKEN_REJECT);
            assertRejected(userStatus("pat-secret"), TOKEN_REJECT);
            // 헤더 이름도 경로 규약대로다 — X-Internal-Secret으로는 안 열린다.
            assertRejected(call(put("/internal/users/1/status"), "X-Internal-Secret", "sync-token"), TOKEN_REJECT);
        }

        @Test
        void 매핑되지_않은_내부_경로는_어떤_비밀로도_열리지_않는다() throws Exception {
            for (String s : new String[]{"pat-secret", "agent-secret", "legacy-secret"}) {
                assertRejected(call(post("/internal/unknown"), "X-Internal-Secret", s), SECRET_REJECT);
            }
        }

        @Test
        void 아웃바운드_org_신원_토큰은_ORG_IDENTITY_TOKEN이다() {
            assertThat(env.getProperty("platform.internal.org-identity-token")).isEqualTo("identity-token");
        }
    }

    /** 새 변수 없이 옛 변수만 — 오늘 배포된 compose 그대로. 세 경로 모두 옛 값으로 열린다. */
    @Nested
    @TestPropertySource(properties = {
            "AGENT_INTERNAL_SECRET=legacy-secret",
            "ORG_INTERNAL_TOKEN=legacy-token"})
    class LegacyFallback extends Base {

        @Test
        void 옛_AGENT_INTERNAL_SECRET으로_PAT와_에이전트_경로가_모두_열린다() throws Exception {
            assertPassed(patExchange("legacy-secret"));
            assertPassed(patStats("legacy-secret"));
            assertPassed(agents("legacy-secret"));
            assertPassed(serviceTokens("legacy-secret"));
        }

        @Test
        void 옛_ORG_INTERNAL_TOKEN으로_계정_동기화가_열리고_아웃바운드도_같은_값이다() throws Exception {
            assertPassed(userStatus("legacy-token"));
            assertRejected(userStatus("legacy-secret"), TOKEN_REJECT);
            assertThat(env.getProperty("platform.internal.org-identity-token")).isEqualTo("legacy-token");
        }

        @Test
        void 옛_비밀끼리는_섞이지_않는다() throws Exception {
            assertRejected(patExchange("legacy-token"), SECRET_REJECT);
        }
    }

    /** 무중단 회전 — 수신 쪽에 "신,구"를 넣으면 두 값 모두 통과하고 제3의 값은 거부된다. */
    @Nested
    @TestPropertySource(properties = {
            "AUTH_PAT_EXCHANGE_SECRET=pat-new, pat-old",
            "AUTH_AGENT_ADMIN_SECRET=agent-new,agent-old",
            "AUTH_ACCOUNT_SYNC_TOKEN=sync-new,sync-old"})
    class Rotation extends Base {

        @Test
        void 신_구_두_값이_모두_통과한다() throws Exception {
            assertPassed(patExchange("pat-new"));
            assertPassed(patExchange("pat-old"));
            assertPassed(serviceTokens("agent-new"));
            assertPassed(serviceTokens("agent-old"));
            assertPassed(userStatus("sync-new"));
            assertPassed(userStatus("sync-old"));
        }

        @Test
        void 목록_밖의_값과_다른_집합의_값은_거부된다() throws Exception {
            assertRejected(patExchange("pat-third"), SECRET_REJECT);
            assertRejected(patExchange("agent-new"), SECRET_REJECT);
            assertRejected(serviceTokens("pat-old"), SECRET_REJECT);
            assertRejected(userStatus("pat-new"), TOKEN_REJECT);
        }
    }

    /** 새·옛 변수가 모두 비면 지금처럼 전부 fail-closed. */
    @Nested
    @TestPropertySource(properties = {
            "AUTH_PAT_EXCHANGE_SECRET=",
            "AUTH_AGENT_ADMIN_SECRET=",
            "AUTH_ACCOUNT_SYNC_TOKEN=",
            "AGENT_INTERNAL_SECRET=",
            "ORG_INTERNAL_TOKEN="})
    class AllBlank extends Base {

        @Test
        void 모두_비면_세_경로가_전부_거부된다() throws Exception {
            assertRejected(patExchange(""), SECRET_REJECT);
            assertRejected(patStats("anything"), SECRET_REJECT);
            assertRejected(agents(""), SECRET_REJECT);
            assertRejected(serviceTokens("anything"), SECRET_REJECT);
            assertRejected(userStatus(""), TOKEN_REJECT);
            assertRejected(call(put("/internal/users/1/status"), null, null), TOKEN_REJECT);
        }
    }
}
