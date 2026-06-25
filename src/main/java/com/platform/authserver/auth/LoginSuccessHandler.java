package com.platform.authserver.auth;

import com.platform.authserver.token.CookieFactory;
import com.platform.authserver.token.RefreshTokenService;
import com.platform.authserver.user.User;
import com.platform.authserver.user.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * Keycloak OIDC 로그인 성공 후:
 * 1) JIT user 프로비저닝  2) 자체 refresh token 발급(+Keycloak id_token 보관)
 * 3) RT 쿠키 set  4) 프론트 /app 로 리다이렉트.
 * 자체 AT는 여기서 주지 않는다 — 프론트가 마운트 시 /api/auth/refresh 로 받는다(silent restore).
 */
@Component
public class LoginSuccessHandler implements AuthenticationSuccessHandler {

    private final UserService userService;
    private final RefreshTokenService refreshTokenService;
    private final CookieFactory cookieFactory;
    private final String frontendUrl;

    public LoginSuccessHandler(UserService userService,
                               RefreshTokenService refreshTokenService,
                               CookieFactory cookieFactory,
                               @Value("${platform.frontend-url}") String frontendUrl) {
        this.userService = userService;
        this.refreshTokenService = refreshTokenService;
        this.cookieFactory = cookieFactory;
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
        var issued = refreshTokenService.issue(user, kcIdToken);

        response.addHeader(HttpHeaders.SET_COOKIE, cookieFactory.refreshCookie(issued.rawToken()).toString());
        response.sendRedirect(frontendUrl + "/app");
    }
}
