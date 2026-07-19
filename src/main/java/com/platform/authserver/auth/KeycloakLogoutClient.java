package com.platform.authserver.auth;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

import java.net.http.HttpClient;
import java.time.Duration;

/**
 * Keycloak 백채널(서버-서버) 로그아웃.
 *
 * platform-bff 는 client_secret 을 가진 컨피덴셜 클라이언트이므로, 저장해 둔 KC refresh_token 으로
 * end_session 엔드포인트를 직접 호출해 SSO 세션을 끊는다. 브라우저 리다이렉트(id_token_hint) 방식과 달리
 * id_token 만료에 영향받지 않아 "재로그인 즉시" 문제를 막는다.
 *
 * 실패해도 예외를 던지지 않는다 — 로컬 세션(자체 RT/쿠키)은 이미 정리됐으므로 로그아웃 자체는 성공시킨다.
 */
@Component
public class KeycloakLogoutClient {

    private static final Logger log = LoggerFactory.getLogger(KeycloakLogoutClient.class);

    private final RestClient restClient;
    private final String logoutEndpoint;
    private final String clientId;
    private final String clientSecret;

    public KeycloakLogoutClient(
            @Value("${spring.security.oauth2.client.provider.keycloak.issuer-uri}") String issuerUri,
            @Value("${spring.security.oauth2.client.registration.keycloak.client-id}") String clientId,
            @Value("${spring.security.oauth2.client.registration.keycloak.client-secret}") String clientSecret) {
        this.logoutEndpoint = issuerUri + "/protocol/openid-connect/logout";
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        // Boot 4는 RestClient.Builder 빈을 기본 자동구성하지 않으므로 정적 팩토리로 직접 만든다.
        // KC 행(hang) 시 서블릿 스레드 동반 고갈 방지 — best-effort는 예외는 삼켜도 행은 못 삼킨다.
        // Boot 4.0.6의 ClientHttpRequestFactorySettings/ClientHttpRequestFactoryBuilder는
        // spring-boot-http-client 모듈에 있으나 이 프로젝트 classpath엔 없다(어떤 starter도 끌어오지 않음) —
        // 새 의존성 추가 대신 spring-web에 이미 있는 JdkClientHttpRequestFactory로 직접 타임아웃 설정.
        HttpClient httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(2))
                .build();
        JdkClientHttpRequestFactory requestFactory = new JdkClientHttpRequestFactory(httpClient);
        requestFactory.setReadTimeout(Duration.ofSeconds(3));
        this.restClient = RestClient.builder()
                .requestFactory(requestFactory)
                .build();
    }

    /** KC SSO 세션을 종료한다. refresh_token 이 없거나 호출 실패 시 경고만 남기고 조용히 넘어간다. */
    public void logout(String kcRefreshToken) {
        if (kcRefreshToken == null || kcRefreshToken.isBlank()) {
            log.warn("KC refresh_token 없음 — 백채널 로그아웃 생략. KC SSO 세션이 남아 재로그인이 즉시 될 수 있다.");
            return;
        }
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("client_id", clientId);
        form.add("client_secret", clientSecret);
        form.add("refresh_token", kcRefreshToken);
        try {
            restClient.post()
                    .uri(logoutEndpoint)
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body(form)
                    .retrieve()
                    .toBodilessEntity();
            log.debug("KC 백채널 로그아웃 성공");
        } catch (RestClientException e) {
            log.warn("KC 백채널 로그아웃 실패: {}", e.getMessage());
        }
    }
}
