package com.platform.authserver.auth;

import com.platform.authserver.token.CookieFactory;
import com.platform.authserver.token.RefreshTokenService;
import com.platform.authserver.user.User;
import com.platform.authserver.user.UserService;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * returnTo(post_login_redirect) 쿠키 계약:
 * - 유효(상대경로)면 frontendUrl+경로로 복귀 + 쿠키 삭제(일회용)
 * - 절대 URL / "//host" / 부재 → /app 폴백 (오픈 리다이렉트 방어)
 */
class LoginSuccessHandlerTest {

    UserService userService = mock(UserService.class);
    RefreshTokenService refreshTokenService = mock(RefreshTokenService.class);
    OAuth2AuthorizedClientService authorizedClientService = mock(OAuth2AuthorizedClientService.class);
    LoginSuccessHandler handler;

    @BeforeEach
    void setUp() {
        when(userService.provision(any(), any(), any(), any(), any())).thenReturn(new User("kc-1"));
        when(refreshTokenService.issue(any(), any(), any()))
                .thenReturn(new RefreshTokenService.Issued("raw-rt", "kc-id-token"));
        handler = new LoginSuccessHandler(userService, refreshTokenService,
                new CookieFactory(60, false), authorizedClientService, "http://localhost");
    }

    private OAuth2AuthenticationToken authentication() {
        OidcIdToken idToken = new OidcIdToken(
                "tok", Instant.now(), Instant.now().plusSeconds(60),
                Map.of("sub", "kc-1", "email", "a@b.com", "name", "Alice"));
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
}
