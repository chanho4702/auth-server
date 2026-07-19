package com.platform.authserver.config;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * docker 프로필 분리 수평(split-horizon) ClientRegistration이 브라우저(front)/서버-서버(back)
 * 엔드포인트를 올바르게 나눠 구성하는지 검증한다 — Spring 컨텍스트 없이 빈 팩토리 메서드를 직접 호출.
 */
class ContainerClientRegistrationConfigTest {

    private static final String CLIENT_ID = "platform-bff";
    private static final String CLIENT_SECRET = "secret";
    private static final String BACK_BASE = "http://keycloak:8080/realms/sso-demo";
    private static final String FRONT_ISSUER = "http://localhost:8080/realms/sso-demo";

    private ClientRegistration keycloakRegistration() {
        ContainerClientRegistrationConfig config = new ContainerClientRegistrationConfig();
        ClientRegistrationRepository repository =
                config.clientRegistrationRepository(CLIENT_ID, CLIENT_SECRET, BACK_BASE, FRONT_ISSUER);
        assertThat(repository).isInstanceOf(InMemoryClientRegistrationRepository.class);
        return repository.findByRegistrationId("keycloak");
    }

    @Test
    void issuerAndAuthorizationUriUseFrontOrigin() {
        ClientRegistration.ProviderDetails provider = keycloakRegistration().getProviderDetails();

        assertThat(provider.getIssuerUri()).isEqualTo(FRONT_ISSUER);
        assertThat(provider.getAuthorizationUri())
                .isEqualTo(FRONT_ISSUER + "/protocol/openid-connect/auth");
    }

    @Test
    void tokenAndJwkSetUriUseBackContainerDns() {
        ClientRegistration.ProviderDetails provider = keycloakRegistration().getProviderDetails();

        assertThat(provider.getTokenUri()).isEqualTo(BACK_BASE + "/protocol/openid-connect/token");
        assertThat(provider.getJwkSetUri()).isEqualTo(BACK_BASE + "/protocol/openid-connect/certs");
    }

    @Test
    void userInfoAbsentSoPrincipalComesFromIdToken() {
        // KC는 userinfo 요청 호스트를 토큰 iss와 대조한다 — 백채널(keycloak:8080) 호출은 무조건 401.
        // userInfoUri가 없으면 OidcUserService가 userinfo를 건너뛰고 ID 토큰 클레임으로 principal 구성.
        ClientRegistration.ProviderDetails provider = keycloakRegistration().getProviderDetails();

        assertThat(provider.getUserInfoEndpoint().getUri()).isNull();
        assertThat(provider.getUserInfoEndpoint().getUserNameAttributeName()).isEqualTo("sub");
    }

    @Test
    void redirectUriAndScopesAndAuthMethod() {
        ClientRegistration registration = keycloakRegistration();

        assertThat(registration.getRedirectUri()).isEqualTo("{baseUrl}/login/oauth2/code/keycloak");
        assertThat(registration.getScopes()).contains("openid", "profile", "email");
        assertThat(registration.getClientAuthenticationMethod())
                .isEqualTo(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
    }
}
