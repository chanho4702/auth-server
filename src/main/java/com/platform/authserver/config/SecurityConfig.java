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
    SecurityFilterChain apiChain(HttpSecurity http, JwtAuthenticationConverter converter) throws Exception {
        http
                .securityMatcher("/api/me", "/api/auth/agents", "/api/auth/agents/**", "/api/auth/tokens", "/api/auth/tokens/**")
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/auth/agents", "/api/auth/agents/**").hasRole("ADMIN")
                        .anyRequest().authenticated())
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt -> jwt.jwtAuthenticationConverter(converter)))
                .addFilterBefore(new PatJwtGuardFilter(), AuthorizationFilter.class);
        return http.build();
    }

    /**
     * 게이트웨이가 라우팅하지 않는 클러스터 내부 전용 경로. JWT가 아니라
     * {@link InternalSecretFilter}가 인증을 전담하므로 authorizeHttpRequests는 permitAll —
     * 필터가 시크릿 불일치/미설정 시 403으로 직접 응답하고 체인을 끊는다.
     *
     * <p>{@code InternalSecretFilter}는 여기서 {@code new}로 직접 만든다(빈으로 등록하지
     * 않음) — Boot가 {@code Filter} 빈을 서블릿 컨테이너 레벨(/*)에도 자동 등록하는 것을
     * 피하기 위함(C1, 클래스 주석 참고). 이 체인에만 등록되는 지역 인스턴스다.
     */
    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE + 1)
    SecurityFilterChain internalChain(HttpSecurity http,
                                       @Value("${platform.agent.internal-secret:}") String internalSecret) throws Exception {
        http
                .securityMatcher("/internal/**")
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                .addFilterBefore(new InternalSecretFilter(internalSecret), UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    /**
     * {@code /invite/**}는 로그인 <b>전</b>에 열려야 한다 — 초대 링크를 타고 온 사람은 아직 계정이
     * 없거나 로그인하지 않은 상태다. 이 경로는 토큰을 세션에 담고 Keycloak 로그인으로 보내기만 한다.
     *
     * <p>인가 요청 resolver를 갈아 끼우는 것은 그 세션 값으로 {@code login_hint}를 붙이기 위해서다.
     */
    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE + 2)
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
