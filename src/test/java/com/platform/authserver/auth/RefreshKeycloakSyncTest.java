package com.platform.authserver.auth;

import com.platform.authserver.token.RefreshTokenService;
import com.platform.authserver.user.User;
import com.platform.authserver.user.UserService;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 리프레시 회전 때 Keycloak 계정·롤 재확인(권한·계정 점검 M1 일부).
 *
 * <p>계약: KC 롤이 바뀌면 새 AT에 바로 실린다 / KC에서 잠기거나 지워지면 401 + 그 사람의 RT 전부 폐기 /
 * KC 장애면 마지막으로 맞춘 roles가 max-stale 안일 때만 통과, 넘으면 503(쿠키 유지).
 */
@SpringBootTest(properties = "platform.keycloak-sync.max-stale-seconds=3600")
@ActiveProfiles("test")
@Import(com.platform.authserver.TestOAuth2ClientConfig.class)
class RefreshKeycloakSyncTest {

    @Autowired WebApplicationContext context;
    @MockitoBean RefreshTokenService refreshTokenService;
    @MockitoBean KeycloakLogoutClient keycloakLogoutClient;
    @MockitoBean KeycloakAccountClient keycloakAccounts;
    @MockitoBean UserService userService;
    MockMvc mvc;
    User user;

    @BeforeEach
    void setup() {
        mvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
        user = new User("kc-sub-42");
        ReflectionTestUtils.setField(user, "id", 42L);
        user.setEmail("a@b.com");
        user.setName("Alice");
        user.setRoles(List.of("USER", "ADMIN"));
        user.setProvider("KEYCLOAK");
        user.setRolesSyncedAt(Instant.now());
        when(refreshTokenService.ownerOf(eq("raw-rt"))).thenReturn(Optional.of(user));
        when(refreshTokenService.rotate(eq("raw-rt")))
                .thenReturn(new RefreshTokenService.Rotated(user, "new-rt", "kc-id"));
    }

    private static KeycloakAccountClient.Verdict verdict(KeycloakAccountClient.Verdict.Kind kind) {
        return new KeycloakAccountClient.Verdict(kind, List.of());
    }

    @SuppressWarnings("unchecked")
    private static List<String> rolesOf(MvcResult result) throws Exception {
        String at = com.jayway.jsonpath.JsonPath.read(result.getResponse().getContentAsString(), "$.accessToken");
        String payload = new String(Base64.getUrlDecoder().decode(at.split("\\.")[1]), StandardCharsets.UTF_8);
        return com.jayway.jsonpath.JsonPath.read(payload, "$.roles");
    }

    /** KC에서 ADMIN을 회수하면 다음 회전의 AT부터 빠진다 — 예전에는 최대 90일 동안 옛 롤이 실렸다. */
    @Test
    void KC_롤_회수가_새_AT에_바로_반영된다() throws Exception {
        when(keycloakAccounts.check("kc-sub-42"))
                .thenReturn(new KeycloakAccountClient.Verdict(KeycloakAccountClient.Verdict.Kind.ACTIVE, List.of("USER")));

        MvcResult result = mvc.perform(post("/api/auth/refresh").cookie(new Cookie("refresh_token", "raw-rt")))
                .andExpect(status().isOk())
                .andReturn();

        assertThat(rolesOf(result)).containsExactly("USER");
        verify(userService).applyKeycloakRoles(42L, List.of("USER"));
    }

    @Test
    void KC에서_잠긴_계정은_401이고_RT를_전부_폐기한다() throws Exception {
        when(keycloakAccounts.check("kc-sub-42")).thenReturn(verdict(KeycloakAccountClient.Verdict.Kind.DISABLED));

        mvc.perform(post("/api/auth/refresh").cookie(new Cookie("refresh_token", "raw-rt")))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string("Set-Cookie", org.hamcrest.Matchers.containsString("refresh_token=;")))
                .andExpect(jsonPath("$.error").value("invalid_refresh_token"));

        verify(userService).closeSessions(42L);
        // 부정 판정은 캐시에 남겨 둔다(Codex P2) — 지우면 폐기된 옛 RT의 반복 리프레시가 매번 KC+폐기 쿼리를 부른다.
        verify(keycloakAccounts, never()).evict(anyString());
        verify(refreshTokenService, never()).rotate(anyString());
    }

    /** 캐시에서 온 부정 판정 — 처음 판정 때 이미 닫았으므로 401만, 폐기 쿼리를 다시 돌리지 않는다(Codex P2). */
    @Test
    void 캐시된_부정_판정이면_폐기_쿼리_없이_401만() throws Exception {
        when(keycloakAccounts.check("kc-sub-42")).thenReturn(
                new KeycloakAccountClient.Verdict(KeycloakAccountClient.Verdict.Kind.DISABLED, List.of(), true));

        mvc.perform(post("/api/auth/refresh").cookie(new Cookie("refresh_token", "raw-rt")))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("invalid_refresh_token"));

        verify(userService, never()).closeSessions(anyLong());
        verify(keycloakAccounts, never()).evict(anyString());
        verify(refreshTokenService, never()).rotate(anyString());
    }

    @Test
    void KC에서_삭제된_계정도_401이고_RT를_전부_폐기한다() throws Exception {
        when(keycloakAccounts.check("kc-sub-42")).thenReturn(verdict(KeycloakAccountClient.Verdict.Kind.GONE));

        mvc.perform(post("/api/auth/refresh").cookie(new Cookie("refresh_token", "raw-rt")))
                .andExpect(status().isUnauthorized());

        verify(userService).closeSessions(42L);
        verify(refreshTokenService, never()).rotate(anyString());
    }

    /** KC 장애 + 최근에 맞춘 roles → 가용성 우선(전원 로그아웃 방지). 저장된 roles를 그대로 쓴다. */
    @Test
    void KC_장애여도_roles가_신선하면_저장된_roles로_통과한다() throws Exception {
        when(keycloakAccounts.check("kc-sub-42")).thenReturn(verdict(KeycloakAccountClient.Verdict.Kind.UNAVAILABLE));

        MvcResult result = mvc.perform(post("/api/auth/refresh").cookie(new Cookie("refresh_token", "raw-rt")))
                .andExpect(status().isOk())
                .andReturn();

        assertThat(rolesOf(result)).containsExactly("USER", "ADMIN");
        verify(userService, never()).applyKeycloakRoles(anyLong(), any());
        verify(userService, never()).closeSessions(anyLong());
    }

    /** KC 장애가 max-stale을 넘기면 503 — 쿠키는 지우지 않아 KC가 돌아오면 같은 쿠키로 회복된다. */
    @Test
    void KC_장애가_길어져_roles가_오래되면_503이고_쿠키를_지우지_않는다() throws Exception {
        user.setRolesSyncedAt(Instant.now().minus(2, ChronoUnit.HOURS));
        when(keycloakAccounts.check("kc-sub-42")).thenReturn(verdict(KeycloakAccountClient.Verdict.Kind.UNAVAILABLE));

        mvc.perform(post("/api/auth/refresh").cookie(new Cookie("refresh_token", "raw-rt")))
                .andExpect(status().isServiceUnavailable())
                .andExpect(header().doesNotExist("Set-Cookie"))
                .andExpect(jsonPath("$.error").value("auth_unavailable"));

        verify(refreshTokenService, never()).rotate(anyString());
        verify(userService, never()).closeSessions(anyLong());
    }

    /** 미설정(시크릿 없음)·에이전트는 예전처럼 로그인 때 roles 그대로. */
    @Test
    void 확인을_건너뛰면_예전_동작과_같다() throws Exception {
        when(keycloakAccounts.check("kc-sub-42")).thenReturn(verdict(KeycloakAccountClient.Verdict.Kind.SKIPPED));

        MvcResult result = mvc.perform(post("/api/auth/refresh").cookie(new Cookie("refresh_token", "raw-rt")))
                .andExpect(status().isOk())
                .andReturn();

        assertThat(rolesOf(result)).containsExactly("USER", "ADMIN");
        verify(userService, never()).applyKeycloakRoles(anyLong(), any());
    }
}
