package com.platform.authserver.auth;

import com.platform.authserver.invite.InviteController;
import com.platform.authserver.invite.OrgInternalClient;
import com.platform.authserver.token.CookieFactory;
import com.platform.authserver.token.RefreshTokenService;
import com.platform.authserver.user.User;
import com.platform.authserver.user.UserService;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * 로그인 성공 후처리.
 *
 * 초대 계약: 세션에 초대 토큰이 있으면 org 에 수락을 알린다(그 사람의 id 가 처음 생기는 순간이다).
 * org 호출이 실패해도 로그인은 계속한다 — 이메일 대조 경로가 남아 있고, org 가 잠깐 안 뜬다고
 * 로그인을 막을 이유가 없다.
 *
 * returnTo(post_login_redirect) 쿠키 계약:
 * - 유효(상대경로)면 frontendUrl+경로로 복귀 + 쿠키 삭제(일회용)
 * - 절대 URL / "//host" / 부재 → /app 폴백 (오픈 리다이렉트 방어)
 */
class LoginSuccessHandlerTest {

    UserService userService = mock(UserService.class);
    RefreshTokenService refreshTokenService = mock(RefreshTokenService.class);
    OAuth2AuthorizedClientService authorizedClientService = mock(OAuth2AuthorizedClientService.class);
    OrgInternalClient orgClient = mock(OrgInternalClient.class);
    LoginSuccessHandler handler;

    @BeforeEach
    void setUp() {
        when(userService.provision(any(), any(), any(), any(), any())).thenReturn(userWithId(42L));
        when(refreshTokenService.issue(any(), any(), any()))
                .thenReturn(new RefreshTokenService.Issued("raw-rt", "kc-id-token"));
        handler = new LoginSuccessHandler(userService, refreshTokenService,
                new CookieFactory(60, false), authorizedClientService, orgClient, "http://localhost");
    }

    /** users.id 는 DB 시퀀스라 테스트에서는 리플렉션으로 심는다 — 초대 수락 통보가 이 값을 싣는다. */
    private static User userWithId(long id) {
        User user = new User("kc-1");
        try {
            var field = User.class.getDeclaredField("id");
            field.setAccessible(true);
            field.set(user, id);
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException(e);
        }
        return user;
    }

    private OAuth2AuthenticationToken authentication() {
        return authentication(Map.of("sub", "kc-1", "email", "a@b.com", "name", "Alice"));
    }

    private OAuth2AuthenticationToken authentication(Map<String, Object> claims) {
        OidcIdToken idToken = new OidcIdToken("tok", Instant.now(), Instant.now().plusSeconds(60), claims);
        return new OAuth2AuthenticationToken(new DefaultOidcUser(List.of(), idToken), List.of(), "keycloak");
    }

    private MockHttpServletResponse loginWith(Cookie... cookies) throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        if (cookies.length > 0) request.setCookies(cookies);
        MockHttpServletResponse response = new MockHttpServletResponse();
        handler.onAuthenticationSuccess(request, response, authentication());
        return response;
    }

    @Test
    void redirectsToReturnToPathAndDeletesCookie() throws Exception {
        MockHttpServletResponse response = loginWith(new Cookie("post_login_redirect", "/wiki/pages/3"));

        assertThat(response.getRedirectedUrl()).isEqualTo("http://localhost/wiki/pages/3");
        assertThat(response.getHeaders("Set-Cookie"))
                .anyMatch(h -> h.startsWith("post_login_redirect=;") && h.contains("Max-Age=0"));
    }

    @Test
    void fallsBackToAppWhenCookieAbsent() throws Exception {
        MockHttpServletResponse response = loginWith();

        assertThat(response.getRedirectedUrl()).isEqualTo("http://localhost/app");
    }

    @Test
    void rejectsAbsoluteUrl() throws Exception {
        MockHttpServletResponse response = loginWith(new Cookie("post_login_redirect", "https://evil.com/phish"));

        assertThat(response.getRedirectedUrl()).isEqualTo("http://localhost/app");
        // 무효 값이라도 쿠키는 소비(삭제)한다
        assertThat(response.getHeaders("Set-Cookie"))
                .anyMatch(h -> h.startsWith("post_login_redirect=;") && h.contains("Max-Age=0"));
    }

    @Test
    void rejectsSchemeRelativeUrl() throws Exception {
        MockHttpServletResponse response = loginWith(new Cookie("post_login_redirect", "//evil.com/phish"));

        assertThat(response.getRedirectedUrl()).isEqualTo("http://localhost/app");
    }

    @Test
    void 초대_세션이면_org에_수락을_알리고_토큰을_지운다() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpSession session = new MockHttpSession();
        session.setAttribute(InviteController.TOKEN_ATTR, "tok-123");
        session.setAttribute(InviteController.EMAIL_ATTR, "a@b.com");
        request.setSession(session);

        handler.onAuthenticationSuccess(request, new MockHttpServletResponse(), authentication());

        verify(orgClient).accept(eq("tok-123"), eq(42L), eq("a@b.com"), any(), any());
        // 일회용 — 남겨 두면 다음 로그인이 지난 초대를 다시 들고 간다
        assertThat(session.getAttribute(InviteController.TOKEN_ATTR)).isNull();
        assertThat(session.getAttribute(InviteController.EMAIL_ATTR)).isNull();
    }

    @Test
    void 초대_세션이_아니면_org를_부르지_않는다() throws Exception {
        loginWith();

        verify(orgClient, never()).accept(any(), anyLong(), any(), any(), any());
    }

    @Test
    void org_호출이_실패해도_로그인은_계속된다() throws Exception {
        doThrow(new RuntimeException("org down"))
                .when(orgClient).accept(any(), anyLong(), any(), any(), any());
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpSession session = new MockHttpSession();
        session.setAttribute(InviteController.TOKEN_ATTR, "tok-123");
        request.setSession(session);
        MockHttpServletResponse response = new MockHttpServletResponse();

        handler.onAuthenticationSuccess(request, response, authentication());

        assertThat(response.getRedirectedUrl()).isEqualTo("http://localhost/app");
    }

    /**
     * Codex P2 — 비활성(org에서 정지·퇴사 전파) 사용자가 OIDC 로그인에 성공해도 새 리프레시 토큰을 발급하지 않는다.
     * 발급하면 재활성 직후 그 토큰이 바로 살아난다. 쿠키도 없고, 초대 수락도 하지 않고, 403 안내로 끝낸다.
     */
    @Test
    void 비활성_사용자는_리프레시_토큰을_받지_못하고_403_안내로_끝난다() throws Exception {
        User disabled = userWithId(42L);
        disabled.setEnabled(false);
        when(userService.provision(any(), any(), any(), any(), any())).thenReturn(disabled);
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpSession session = new MockHttpSession();
        session.setAttribute(InviteController.TOKEN_ATTR, "invite-token");
        request.setSession(session);
        MockHttpServletResponse response = new MockHttpServletResponse();

        handler.onAuthenticationSuccess(request, response, authentication());

        verify(refreshTokenService, never()).issue(any(), any(), any());
        verify(orgClient, never()).accept(any(), anyLong(), any(), any(), any());
        assertThat(response.getStatus()).isEqualTo(403);
        assertThat(response.getHeaders("Set-Cookie")).noneMatch(c -> c.startsWith(CookieFactory.COOKIE_NAME + "=raw"));
        assertThat(response.getRedirectedUrl()).isNull();
        assertThat(response.getContentAsString()).contains("비활성화된 계정");
        assertThat(session.isInvalid()).isTrue();
    }

    /**
     * 권한·계정 점검 Top 5-①: org CheckPermission은 구성원 행이 없으면 PENDING으로 거부하므로, 로그인 성공 순간 행을 보장한다.
     * 초대 수락 뒤에 부른다(수락이 ACTIVE로 만든 행은 ensure가 그대로 둔다).
     */
    @Test
    void 로그인_성공이면_초대_수락_뒤에_org_구성원_행을_보장한다() throws Exception {
        User u = userWithId(42L);
        u.setEmail("a@b.com");
        u.setName("Alice");
        u.setProvider("GOOGLE");
        when(userService.provision(any(), any(), any(), any(), any())).thenReturn(u);
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpSession session = new MockHttpSession();
        session.setAttribute(InviteController.TOKEN_ATTR, "tok-123");
        request.setSession(session);

        handler.onAuthenticationSuccess(request, new MockHttpServletResponse(), authentication());

        var order = org.mockito.Mockito.inOrder(orgClient);
        order.verify(orgClient).accept(eq("tok-123"), eq(42L), eq("a@b.com"), any(), any());
        order.verify(orgClient).ensureMember(42L, "a@b.com", "Alice", "GOOGLE");
    }

    @Test
    void 구성원_행_보장이_실패해도_로그인은_계속된다() throws Exception {
        doThrow(new RuntimeException("org down")).when(orgClient).ensureMember(anyLong(), any(), any(), any());

        MockHttpServletResponse response = loginWith();

        assertThat(response.getRedirectedUrl()).isEqualTo("http://localhost/app");
    }

    /** 점검 m5: org가 검증 안 된 이메일의 링크 수락을 거절할 수 있게 email_verified를 그대로 넘긴다. */
    @Test
    void 초대_수락에_email_verified를_싣는다() throws Exception {
        for (boolean verified : new boolean[]{true, false}) {
            org.mockito.Mockito.clearInvocations(orgClient);
            MockHttpServletRequest request = new MockHttpServletRequest();
            MockHttpSession session = new MockHttpSession();
            session.setAttribute(InviteController.TOKEN_ATTR, "tok-123");
            request.setSession(session);

            handler.onAuthenticationSuccess(request, new MockHttpServletResponse(), authentication(Map.of(
                    "sub", "kc-1", "email", "a@b.com", "name", "Alice", "email_verified", verified)));

            verify(orgClient).accept(eq("tok-123"), eq(42L), eq("a@b.com"), any(), eq(verified));
        }
    }

    @Test
    void 비활성_사용자는_구성원_행_보장도_하지_않는다() throws Exception {
        User disabled = userWithId(42L);
        disabled.setEnabled(false);
        when(userService.provision(any(), any(), any(), any(), any())).thenReturn(disabled);

        loginWith();

        verify(orgClient, never()).ensureMember(anyLong(), any(), any(), any());
    }
}
