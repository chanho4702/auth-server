package com.platform.authserver.user;

import com.platform.authserver.TestOAuth2ClientConfig;
import com.platform.authserver.pat.PatScopes;
import com.platform.authserver.pat.PersonalAccessTokenRepository;
import com.platform.authserver.pat.PersonalAccessTokenService;
import com.platform.authserver.token.RefreshTokenRepository;
import com.platform.authserver.token.RefreshTokenService;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * P-02 — org-service가 구성원을 정지·퇴사시키면 이 내부 API로 계정을 닫는다. 닫힌 계정은
 * ① 리프레시 토큰이 전부 폐기돼 /api/auth/refresh가 401 ② PAT 교환이 401. 다시 열면 PAT는 되살아나고
 * (폐기하지 않고 거부만 했으므로) 리프레시 토큰은 폐기된 채로 남는다(재로그인).
 */
@SpringBootTest
@ActiveProfiles("test")
@Import(TestOAuth2ClientConfig.class)
@TestPropertySource(properties = {
        "platform.org.internal-token=test-org-token",
        "platform.agent.internal-secret=test-internal-secret"})
class InternalUserStatusTest {

    @Autowired WebApplicationContext context;
    @Autowired UserRepository users;
    @Autowired RefreshTokenRepository refreshTokens;
    @Autowired RefreshTokenService refreshTokenService;
    @Autowired PersonalAccessTokenRepository pats;
    @Autowired PersonalAccessTokenService patService;

    MockMvc mvc;
    User alice;

    @BeforeEach
    void setup() {
        mvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
        pats.deleteAll();
        refreshTokens.deleteAll();
        users.deleteAll();
        alice = new User("kc-alice-" + System.nanoTime());
        alice.setEmail("alice@demo.com");
        alice.setName("앨리스");
        alice.setRoles(List.of("USER"));
        alice.setProvider("GOOGLE");
        alice = users.save(alice);
    }

    private ResultActions setStatus(long id, String body, String header, String value) throws Exception {
        var req = put("/internal/users/" + id + "/status").contentType(MediaType.APPLICATION_JSON).content(body);
        if (header != null) req = req.header(header, value);
        return mvc.perform(req);
    }

    private ResultActions refresh(String rawRt) throws Exception {
        return mvc.perform(post("/api/auth/refresh").cookie(new Cookie("refresh_token", rawRt)));
    }

    private ResultActions exchange(String rawPat) throws Exception {
        return mvc.perform(post("/internal/pat/exchange").header("X-Internal-Secret", "test-internal-secret")
                .contentType(MediaType.APPLICATION_JSON).content("{\"token\":\"" + rawPat + "\"}"));
    }

    @Test
    void 계정을_닫으면_리프레시_토큰이_전부_폐기되고_PAT_교환이_거부된다() throws Exception {
        String rt1 = refreshTokenService.issue(alice, "kc-id", "kc-rt").rawToken();  // 브라우저 A
        String rt2 = refreshTokenService.issue(alice, "kc-id", "kc-rt").rawToken();  // 브라우저 B(다른 가족)
        String pat = patService.create(alice.getId(), "CI", 90, List.of(PatScopes.WIKI_READ)).rawToken();
        exchange(pat).andExpect(status().isOk());

        setStatus(alice.getId(), "{\"active\":false}", "X-Internal-Token", "test-org-token")
                .andExpect(status().isNoContent());

        assertThat(users.findById(alice.getId()).orElseThrow().isEnabled()).isFalse();
        assertThat(refreshTokens.findAll()).allMatch(t -> t.isRevoked());
        refresh(rt1).andExpect(status().isUnauthorized());
        refresh(rt2).andExpect(status().isUnauthorized());
        exchange(pat).andExpect(status().isUnauthorized());
    }

    @Test
    void 다시_열면_PAT는_되살아나고_리프레시_토큰은_폐기된_채다() throws Exception {
        String rt = refreshTokenService.issue(alice, "kc-id", "kc-rt").rawToken();
        String pat = patService.create(alice.getId(), "CI", 90, List.of(PatScopes.WIKI_READ)).rawToken();
        setStatus(alice.getId(), "{\"active\":false}", "X-Internal-Token", "test-org-token").andExpect(status().isNoContent());

        setStatus(alice.getId(), "{\"active\":true}", "X-Internal-Token", "test-org-token").andExpect(status().isNoContent());

        assertThat(users.findById(alice.getId()).orElseThrow().isEnabled()).isTrue();
        exchange(pat).andExpect(status().isOk());
        refresh(rt).andExpect(status().isUnauthorized());
    }

    @Test
    void 같은_요청을_반복해도_결과가_같다() throws Exception {
        setStatus(alice.getId(), "{\"active\":false}", "X-Internal-Token", "test-org-token").andExpect(status().isNoContent());
        setStatus(alice.getId(), "{\"active\":false}", "X-Internal-Token", "test-org-token").andExpect(status().isNoContent());
        assertThat(users.findById(alice.getId()).orElseThrow().isEnabled()).isFalse();
    }

    @Test
    void 없는_사용자는_404다() throws Exception {
        setStatus(alice.getId() + 999, "{\"active\":false}", "X-Internal-Token", "test-org-token")
                .andExpect(status().isNotFound());
    }

    @Test
    void active가_없으면_400이다() throws Exception {
        setStatus(alice.getId(), "{}", "X-Internal-Token", "test-org-token").andExpect(status().isBadRequest());
    }

    @Test
    void org_토큰이_없거나_틀리면_403이다() throws Exception {
        setStatus(alice.getId(), "{\"active\":false}", null, null).andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").exists());
        setStatus(alice.getId(), "{\"active\":false}", "X-Internal-Token", "wrong").andExpect(status().isForbidden());
        assertThat(users.findById(alice.getId()).orElseThrow().isEnabled()).isTrue();
    }

    @Test
    void 게이트웨이_에이전트_시크릿으로는_계정을_닫을_수_없고_org_토큰으로는_다른_내부_경로가_안_열린다() throws Exception {
        // 경로별 시크릿 분리(P-07 방향) — 게이트웨이가 쥔 AGENT_INTERNAL_SECRET으로 계정 상태를 바꿀 수 없다
        setStatus(alice.getId(), "{\"active\":false}", "X-Internal-Secret", "test-internal-secret")
                .andExpect(status().isForbidden());
        mvc.perform(post("/internal/pat/exchange").header("X-Internal-Token", "test-org-token")
                        .contentType(MediaType.APPLICATION_JSON).content("{\"token\":\"chanho_pat_x\"}"))
                .andExpect(status().isForbidden());
        assertThat(users.findById(alice.getId()).orElseThrow().isEnabled()).isTrue();
    }
}
