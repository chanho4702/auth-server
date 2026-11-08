package com.platform.authserver.config;

import com.platform.authserver.agent.InternalSecretFilter;
import com.platform.authserver.auth.LoginSuccessHandler;
import com.platform.authserver.invite.InviteLoginHintResolver;
import com.platform.authserver.jwt.JwtKeyProvider;
import com.platform.authserver.pat.PatJwtGuardFilter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.endpoint.RestClientAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.client.RestClient;

import java.net.http.HttpClient;
import java.time.Duration;
import java.util.List;

@Configuration
public class SecurityConfig {

    /** 서명(공개키)뿐 아니라 issuer/audience까지 검증 — 다른 발급자·다른 대상의 토큰 거부. */
    @Bean
    JwtDecoder jwtDecoder(JwtKeyProvider keyProvider,
                          @Value("${platform.issuer}") String issuer,
                          @Value("${platform.audience}") String audience) throws Exception {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withPublicKey(keyProvider.publicKey()).build();
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<Jwt>(
                JwtValidators.createDefaultWithIssuer(issuer),
                new JwtClaimValidator<List<String>>(JwtClaimNames.AUD,
                        aud -> aud != null && aud.contains(audience))));
        return decoder;
    }

    @Bean
    JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter authorities = new JwtGrantedAuthoritiesConverter();
        authorities.setAuthoritiesClaimName("roles");
        authorities.setAuthorityPrefix("ROLE_");
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(authorities);
        return converter;
    }

    /**
     * 자체 JWT 리소스서버 체인. {@code securityMatcher}에 나열된 경로만 이 체인이 잡는다 —
     * {@code /api/auth/**} 아래 경로를 여기 빼먹으면 {@code webChain}의 permitAll로 떨어져
     * 익명에게 열린다. {@code /api/auth/tokens/**}가 그 사례라 회귀 테스트로 고정해 뒀다
     * ({@code PersonalAccessTokenControllerTest.anonymous_list_is_unauthorized}).
     *
     * <p>{@link PatJwtGuardFilter}는 이 체인 안에서 PAT 교환 JWT의 자기 증식 경로
     * ({@code /api/auth/tokens/**}, {@code /api/auth/agents/**})를 막는다. 인가 판정
     * ({@code AuthorizationFilter}) 앞에 두어 PAT 요청이 "권한 없음"보다 구체적인
     * {@code pat_cannot_manage_tokens} 이유를 받게 한다. {@code /api/me}는 목록에 없으므로
     * PAT로 정상 호출된다. {@code InternalSecretFilter}와 같은 이유로 빈이 아니라
     * {@code new}로 만든다(Boot의 서블릿 레벨 자동 등록 회피).
     */
    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    SecurityFilterChain apiChain(HttpSecurity http, JwtAuthenticationConverter converter,
                                 com.platform.authserver.invite.OrgInternalClient orgClient) throws Exception {
        http
                .securityMatcher("/api/me", "/api/auth/agents", "/api/auth/agents/**", "/api/auth/tokens", "/api/auth/tokens/**")
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        // 에이전트 관리는 Keycloak realm 롤 ADMIN이 아니라 org 활성 전역 관리자만(2026-10-24) —
                        // 판정은 OrgGlobalAdminFilter가 한다(403 / org 장애 503). 여기서는 인증만 요구한다.
                        .anyRequest().authenticated())
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt -> jwt.jwtAuthenticationConverter(converter)))
                .addFilterBefore(new PatJwtGuardFilter(), AuthorizationFilter.class)
                .addFilterAfter(new com.platform.authserver.agent.OrgGlobalAdminFilter(orgClient), PatJwtGuardFilter.class);
        return http.build();
    }

    /**
     * org-service 전용 내부 경로 — 구성원 정지·퇴사·해제를 계정에 반영한다(P-02).
     *
     * <p>{@code X-Internal-Secret} 체인들보다 앞에 서서 이 경로만 따로 잡는다. 헤더도 org 쪽 규약({@code X-Internal-Token},
     * 초대 API와 같은 이름)이다. 허용 값은 계정 동기화 전용 {@code platform.internal.account-sync-token}
     * ({@code AUTH_ACCOUNT_SYNC_TOKEN}, 비면 옛 {@code ORG_INTERNAL_TOKEN} — N5). auth → org 아웃바운드 신원 토큰과는 별개다:
     * 그 값을 쥔 쪽(auth)이 이 경로를 여는 것도, 이 값으로 PAT 교환·서비스 토큰 발급을 여는 것도 안 된다. 비어 있으면 fail-closed(403).
     */
    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE + 1)
    SecurityFilterChain orgInternalChain(HttpSecurity http,
                                         @Value("${platform.internal.account-sync-token:}") String accountSyncToken,
                                         @Value("${platform.org.internal-token:}") String legacyOrgToken) throws Exception {
        return internalGate(http, new InternalSecretFilter("X-Internal-Token",
                        InternalSecretFilter.orLegacy(accountSyncToken, legacyOrgToken), "내부 API 토큰이 유효하지 않습니다"),
                "/internal/users/**");
    }

    /**
     * PAT 교환 — 게이트웨이만 부른다({@code /internal/pat/exchange}, 대시보드 집계 {@code /internal/pat/stats}).
     * 허용 값 {@code platform.internal.pat-exchange-secret}({@code AUTH_PAT_EXCHANGE_SECRET}, 비면 옛 {@code AGENT_INTERNAL_SECRET} — N5).
     * 게이트웨이가 쥔 값으로는 에이전트 계정·서비스 토큰을 만들 수 없다.
     */
    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE + 2)
    SecurityFilterChain patInternalChain(HttpSecurity http,
                                         @Value("${platform.internal.pat-exchange-secret:}") String patExchangeSecret,
                                         @Value("${platform.agent.internal-secret:}") String legacySecret) throws Exception {
        return internalGate(http, new InternalSecretFilter(InternalSecretFilter.orLegacy(patExchangeSecret, legacySecret)),
                "/internal/pat/**");
    }

    /**
     * 에이전트 관리 — agent-service만 부른다(에이전트 계정 등록 {@code /internal/agents}, 서비스 토큰 발급 {@code /internal/service-tokens}).
     * 허용 값 {@code platform.internal.agent-admin-secret}({@code AUTH_AGENT_ADMIN_SECRET}, 비면 옛 {@code AGENT_INTERNAL_SECRET} — N5).
     */
    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE + 3)
    SecurityFilterChain agentAdminInternalChain(HttpSecurity http,
                                                @Value("${platform.internal.agent-admin-secret:}") String agentAdminSecret,
                                                @Value("${platform.agent.internal-secret:}") String legacySecret) throws Exception {
        return internalGate(http, new InternalSecretFilter(InternalSecretFilter.orLegacy(agentAdminSecret, legacySecret)),
                "/internal/agents", "/internal/agents/**", "/internal/service-tokens", "/internal/service-tokens/**");
    }

    /**
     * 위 세 체인에 걸리지 않은 나머지 {@code /internal/**} — 어떤 값으로도 열리지 않는다(빈 허용 목록 = 항상 403).
     * 새 내부 경로를 만들면 용도에 맞는 체인의 securityMatcher에 넣어야 열린다 — 잊으면 닫힌 채로 남는다(fail-closed).
     * 이 체인이 없으면 그 경로가 {@code webChain}으로 떨어져 OAuth2 로그인 리다이렉트가 된다.
     */
    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE + 4)
    SecurityFilterChain internalChain(HttpSecurity http) throws Exception {
        return internalGate(http, new InternalSecretFilter(""), "/internal/**");
    }

    /**
     * 게이트웨이가 라우팅하지 않는 클러스터 내부 전용 경로의 공통 골격. JWT가 아니라 {@link InternalSecretFilter}가 인증을
     * 전담하므로 authorizeHttpRequests는 permitAll — 필터가 불일치/미설정 시 403으로 직접 응답하고 체인을 끊는다.
     *
     * <p>{@code InternalSecretFilter}는 호출측에서 {@code new}로 직접 만든다(빈으로 등록하지 않음) — Boot가 {@code Filter}
     * 빈을 서블릿 컨테이너 레벨(/*)에도 자동 등록하는 것을 피하기 위함(C1, 클래스 주석 참고). 이 체인에만 등록되는 지역 인스턴스다.
     */
    private static SecurityFilterChain internalGate(HttpSecurity http, InternalSecretFilter gate, String... paths) throws Exception {
        http
                .securityMatcher(paths)
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                .addFilterBefore(gate, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    /**
     * Actuator 헬스/버전 — 관리자 대시보드가 게이트웨이를 통해 도커 네트워크 안에서 긁는다.
     * 전용 체인으로 분리한 이유는 {@code webChain}에 두면 {@code anyRequest().authenticated()} +
     * {@code oauth2Login}에 걸려 프로브가 Keycloak 로그인으로 302 리다이렉트되기 때문이다.
     * 세션도 만들지 않는다(프로브가 JSESSIONID를 쌓지 않게).
     *
     * <p>여기 나열한 세 경로(health·info·prometheus — 메트릭은 Alloy가 내부망에서 긁는다)만 익명 허용이다. 다른 {@code /actuator/**}는 애초에
     * {@code management.endpoints.web.exposure.include}에 없어 노출되지 않고, 이 체인의
     * securityMatcher에도 걸리지 않아 {@code webChain}의 인증 요구로 떨어진다.
     */
    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE + 5)
    SecurityFilterChain actuatorChain(HttpSecurity http) throws Exception {
        http
                .securityMatcher("/actuator/health", "/actuator/info", "/actuator/prometheus")
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll());
        return http.build();
    }

    /**
     * {@code /invite/**}는 로그인 <b>전</b>에 열려야 한다 — 초대 링크를 타고 온 사람은 아직 계정이
     * 없거나 로그인하지 않은 상태다. 이 경로는 토큰을 세션에 담고 Keycloak 로그인으로 보내기만 한다.
     *
     * <p>인가 요청 resolver를 갈아 끼우는 것은 그 세션 값으로 {@code login_hint}를 붙이기 위해서다.
     */
    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE + 6)
    SecurityFilterChain webChain(HttpSecurity http, LoginSuccessHandler successHandler,
                                 ClientRegistrationRepository clientRegistrations) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/auth/**", "/.well-known/**", "/invite/**", "/error").permitAll()
                        .anyRequest().authenticated())
                .oauth2Login(oauth2 -> oauth2
                        .authorizationEndpoint(endpoint -> endpoint.authorizationRequestResolver(
                                new InviteLoginHintResolver(clientRegistrations, "/oauth2/authorization")))
                        .successHandler(successHandler));
        return http.build();
    }

    /**
     * 로그인(인가 코드 → 토큰 교환) 타임아웃.
     *
     * Boot 4.0.6 의 {@code spring.http.client(s).*} 프로퍼티는 바인딩은 되지만(설정 메타데이터로 실측 확인)
     * Spring Security 의 기본 OAuth2 인가 코드 토큰 응답 클라이언트(RestClientAuthorizationCodeTokenResponseClient)는
     * Boot 의 RestClient.Builder 자동구성을 전혀 거치지 않고 인자 없는 생성자로 자체 RestClient 를 만든다
     * (OAuth2LoginConfigurer.getAccessTokenResponseClient() 바이트코드 실측) — 즉 yml 만으로는 이 경로에
     * 타임아웃이 적용되지 않는다. 대신 이 타입의 빈을 등록하면 OAuth2LoginConfigurer 가 getBeanOrNull 로
     * 자동 탐지해 사용하므로, 여기서 직접 타임아웃 있는 RestClient 를 주입한다.
     *
     * ClientHttpRequestFactorySettings/Builder(spring-boot-http-client 모듈)는 이 프로젝트 classpath에 없어
     * (어떤 starter도 끌어오지 않음, 새 의존성 추가는 범위 밖) spring-web 내장 JdkClientHttpRequestFactory로 대체.
     */
    @Bean
    OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> tokenResponseClient() {
        HttpClient httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(2))
                .build();
        JdkClientHttpRequestFactory requestFactory = new JdkClientHttpRequestFactory(httpClient);
        requestFactory.setReadTimeout(Duration.ofSeconds(3));
        RestClient restClient = RestClient.builder()
                .requestFactory(requestFactory)
                .configureMessageConverters(converters -> converters
                        .disableDefaults()
                        .addCustomConverter(new FormHttpMessageConverter())
                        .addCustomConverter(new OAuth2AccessTokenResponseHttpMessageConverter()))
                .defaultStatusHandler(new OAuth2ErrorResponseErrorHandler())
                .build();
        var client = new RestClientAuthorizationCodeTokenResponseClient();
        client.setRestClient(restClient);
        return client;
    }
}
