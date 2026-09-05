package com.platform.authserver.invite;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 초대 링크로 들어온 세션이면 인가 요청에 {@code login_hint}(초대받은 이메일)를 붙인다.
 *
 * <p>Keycloak 로그인 화면에 주소가 미리 채워진다. 초대받은 주소와 다른 계정으로 로그인하면 org가 수락을
 * 거절하므로, 이 힌트는 실수를 줄이는 편의이자 사실상의 안내다. 힌트가 없어도 로그인 자체는 정상이다.
 *
 * <p>기본 resolver를 위임으로 감싸는 이유는 PKCE·state·nonce 생성 규칙을 그대로 물려받기 위해서다 —
 * 그 부분을 직접 만들면 Spring Security 업그레이드마다 조용히 어긋난다.
 */
public class InviteLoginHintResolver implements OAuth2AuthorizationRequestResolver {

    private final DefaultOAuth2AuthorizationRequestResolver delegate;

    public InviteLoginHintResolver(ClientRegistrationRepository registrations, String baseUri) {
        this.delegate = new DefaultOAuth2AuthorizationRequestResolver(registrations, baseUri);
    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
        return withHint(delegate.resolve(request), request);
    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request, String clientRegistrationId) {
        return withHint(delegate.resolve(request, clientRegistrationId), request);
    }

    private static OAuth2AuthorizationRequest withHint(OAuth2AuthorizationRequest original,
                                                       HttpServletRequest request) {
        if (original == null) return null;
        HttpSession session = request.getSession(false);
        if (session == null) return original;
        Object email = session.getAttribute(InviteController.EMAIL_ATTR);
        if (email == null || email.toString().isBlank()) return original;

        Map<String, Object> params = new LinkedHashMap<>(original.getAdditionalParameters());
        params.put("login_hint", email.toString());
        return OAuth2AuthorizationRequest.from(original).additionalParameters(params).build();
    }
}
