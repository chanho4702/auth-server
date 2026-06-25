package com.platform.authserver;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;

/**
 * 테스트용 OAuth2 ClientRegistrationRepository. 명시적 endpoint(authorization/token/
 * userinfo/jwks)만 사용해 Keycloak 미기동 환경에서도 컨텍스트가 뜬다. 이 빈이 있으면
 * Boot 의 ClientRegistrationRepository 자동설정이 @ConditionalOnMissingBean 으로
 * back off 하여 issuer-uri discovery(네트워크 호출)를 시도하지 않는다.
 */
@TestConfiguration(proxyBeanMethods = false)
public class TestOAuth2ClientConfig {

    @Bean
    ClientRegistrationRepository clientRegistrationRepository() {
        ClientRegistration keycloak = ClientRegistration.withRegistrationId("keycloak")
                .clientId("test")
                .clientSecret("test")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("{baseUrl}/login/oauth2/code/keycloak")
                .scope("openid", "profile", "email")
                .authorizationUri("http://localhost:8080/auth")
                .tokenUri("http://localhost:8080/token")
                .userInfoUri("http://localhost:8080/userinfo")
                .jwkSetUri("http://localhost:8080/jwks")
                .userNameAttributeName(IdTokenClaimNames.SUB)
                .build();
        return new InMemoryClientRegistrationRepository(keycloak);
    }
}
