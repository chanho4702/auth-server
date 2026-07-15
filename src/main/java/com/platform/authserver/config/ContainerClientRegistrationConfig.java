package com.platform.authserver.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;

/**
 * docker 프로필 전용 수동 ClientRegistration — 분리 수평(split-horizon) OIDC.
 *
 * 컨테이너에서는 브라우저(front)와 서버-서버(back)가 서로 다른 호스트로 Keycloak에 닿는다.
 * KC는 토큰 iss를 브라우저 인가 요청 호스트(localhost:8080)로 발급하므로(E2E 실측),
 * Boot의 issuer-uri 디스커버리는 성립 불가: localhost:8080은 컨테이너에서 접근 불가,
 * keycloak:8080으로 디스커버리하면 metadata issuer 불일치로 기동 실패.
 * 그래서 이 빈이 엔드포인트를 직접 구성한다(빈이 있으면 Boot 자동구성·디스커버리는 백오프).
 * spring...provider.keycloak.issuer-uri 프로퍼티는 유지된다 — KeycloakLogoutClient가
 * 백채널 로그아웃 URL로 주입받으므로 docker에서는 keycloak:8080 값이어야 한다.
 */
@Configuration
@Profile("docker")
public class ContainerClientRegistrationConfig {

    @Bean
    ClientRegistrationRepository clientRegistrationRepository(
            @Value("${spring.security.oauth2.client.registration.keycloak.client-id}") String clientId,
            @Value("${spring.security.oauth2.client.registration.keycloak.client-secret}") String clientSecret,
            // 백채널(컨테이너 내부 DNS) — docker에서는 http://keycloak:8080/realms/sso-demo
            @Value("${spring.security.oauth2.client.provider.keycloak.issuer-uri}") String backBase,
            // 브라우저 오리진 = 실제 토큰 iss
            @Value("${KEYCLOAK_FRONT_ISSUER:http://localhost:8080/realms/sso-demo}") String frontIssuer) {
        ClientRegistration keycloak = ClientRegistration.withRegistrationId("keycloak")
                .clientId(clientId)
                .clientSecret(clientSecret)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("{baseUrl}/login/oauth2/code/keycloak")
                .scope("openid", "profile", "email")
                .issuerUri(frontIssuer) // ID 토큰 iss 검증 기준
                .authorizationUri(frontIssuer + "/protocol/openid-connect/auth") // 브라우저가 가는 곳
                .tokenUri(backBase + "/protocol/openid-connect/token")
                .jwkSetUri(backBase + "/protocol/openid-connect/certs")
                .userInfoUri(backBase + "/protocol/openid-connect/userinfo")
                .userNameAttributeName(IdTokenClaimNames.SUB) // 디스커버리 기본과 동일
                .build();
        return new InMemoryClientRegistrationRepository(keycloak);
    }
}
