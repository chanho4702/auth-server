package com.platform.authserver.auth;

import com.platform.authserver.token.CookieFactory;
import com.platform.authserver.token.RefreshTokenService;
import com.platform.authserver.user.User;
import com.platform.authserver.user.UserService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * Keycloak OIDC 로그인 성공 후:
 * 1) JIT user 프로비저닝  2) 자체 refresh token 발급(+Keycloak id_token 보관)
 * 3) RT 쿠키 set  4) returnTo 쿠키(검증 통과 시) 또는 /app 로 리다이렉트.
 * 자체 AT는 여기서 주지 않는다 — 프론트가 마운트 시 /api/auth/refresh 로 받는다(silent restore).
 */
@Component
public class LoginSuccessHandler implements AuthenticationSuccessHandler {

    /** 프론트가 로그인 직전에 심는 복귀 경로 쿠키. 일회용 — 여기서 소비·삭제한다. */
    static final String RETURN_TO_COOKIE = "post_login_redirect";

    private final UserService userService;
    private final RefreshTokenService refreshTokenService;
    private final CookieFactory cookieFactory;
    private final OAuth2AuthorizedClientService authorizedClientService;
    private final String frontendUrl;

    public LoginSuccessHandler(UserService userService,
                               RefreshTokenService refreshTokenService,
                               CookieFactory cookieFactory,
                               OAuth2AuthorizedClientService authorizedClientService,
                               @Value("${platform.frontend-url}") String frontendUrl) {
        this.userService = userService;
        this.refreshTokenService = refreshTokenService;
        this.cookieFactory = cookieFactory;
        this.authorizedClientService = authorizedClientService;
        this.frontendUrl = frontendUrl;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException {
        OidcUser oidcUser = (OidcUser) authentication.getPrincipal();

        User user = userService.provision(
                oidcUser.getSubject(),
                oidcUser.getEmail(),
                oidcUser.getFullName(),
                OidcClaims.roles(oidcUser),
                OidcClaims.provider(oidcUser));

        String kcIdToken = oidcUser.getIdToken().getTokenValue();
        // KC refresh_token 은 OidcUser 가 아니라 authorized client 에 있다. 백채널 로그아웃에 쓴다.
        String kcRefreshToken = extractKcRefreshToken(authentication);
        var issued = refreshTokenService.issue(user, kcIdToken, kcRefreshToken);

        response.addHeader(HttpHeaders.SET_COOKIE, cookieFactory.refreshCookie(issued.rawToken()).toString());

        String rawReturnTo = readCookie(request, RETURN_TO_COOKIE);
        if (rawReturnTo != null) {
            response.addHeader(HttpHeaders.SET_COOKIE, deleteReturnToCookie().toString());
        }
        String target = isSafeRelativePath(rawReturnTo) ? rawReturnTo : "/app";
        response.sendRedirect(frontendUrl + target);
    }

    /** OAuth2 authorized client 에서 Keycloak refresh_token 을 꺼낸다(없으면 null). */
    private String extractKcRefreshToken(Authentication authentication) {
        if (!(authentication instanceof OAuth2AuthenticationToken oauthToken)) {
            return null;
        }
        OAuth2AuthorizedClient client = authorizedClientService.loadAuthorizedClient(
                oauthToken.getAuthorizedClientRegistrationId(), oauthToken.getName());
        if (client == null || client.getRefreshToken() == null) {
            return null;
        }
        return client.getRefreshToken().getTokenValue();
    }

    private static String readCookie(HttpServletRequest request, String name) {
        if (request.getCookies() == null) {
            return null;
        }
        for (Cookie cookie : request.getCookies()) {
            if (name.equals(cookie.getName())) {
                return cookie.getValue();
            }
        }
        return null;
    }

    /** 오픈 리다이렉트 방어: 우리 오리진 안의 상대 경로("/...")만 허용, "//host" 형태 금지. */
    private static boolean isSafeRelativePath(String path) {
        return path != null && path.startsWith("/") && !path.startsWith("//");
    }

    private static ResponseCookie deleteReturnToCookie() {
        return ResponseCookie.from(RETURN_TO_COOKIE, "").path("/").maxAge(0).build();
    }
}
