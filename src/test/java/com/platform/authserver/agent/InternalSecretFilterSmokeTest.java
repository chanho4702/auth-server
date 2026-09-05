package com.platform.authserver.agent;

import com.platform.authserver.TestOAuth2ClientConfig;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * C1 회귀 가드. {@code InternalSecretFilter}가 {@code @Component}였을 때는 Boot가
 * {@code FilterRegistrationBean}으로 서블릿 컨테이너 레벨(url-mapping {@code /*},
 * {@code LOWEST_PRECEDENCE})에도 자동으로 두 번째 필터를 등록했다 — Spring Security 체인이
 * 이미 처리를 끝낸 요청에 대해 "alreadyFiltered" 표시가 없는 채로 다시 한번 돌면서, 시크릿
 * 미설정(운영 기본값)이면 {@code /api/me}·{@code /api/auth/refresh}·JWKS·OAuth2 콜백 등
 * 전체 엔드포인트를 403으로 막는 사고가 됐다. {@code MockMvc(webAppContextSetup)}는 실제
 * 서블릿 컨테이너의 필터 등록 파이프라인을 타지 않아 이 버그를 재현하지 못하므로, 여기서는
 * 반드시 내장 서버(RANDOM_PORT)로 검증한다. {@code TestRestTemplate}은 이 프로젝트의
 * Boot 4 의존성 분리 하에서 클래스패스에 없어(실측) JDK 내장 {@link HttpClient}로 대체.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
@Import(TestOAuth2ClientConfig.class)
class InternalSecretFilterSmokeTest {

    @LocalServerPort
    int port;

    private final HttpClient httpClient = HttpClient.newHttpClient();

    @Test
    void public_endpoint_is_reachable_and_internal_endpoint_is_still_gated() throws Exception {
        HttpResponse<String> jwks = httpClient.send(
                HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/.well-known/jwks.json"))
                        .GET()
                        .build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(jwks.statusCode()).isEqualTo(200);

        // 시크릿 미설정(테스트 프로파일 기본값) — internal 게이트가 다른 경로를 오염시키지
        // 않으면서, 자기 자신은 여전히 잠겨 있어야 한다.
        HttpResponse<String> mint = httpClient.send(
                HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/internal/service-tokens"))
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString("{\"userId\":1}"))
                        .build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(mint.statusCode()).isEqualTo(403);
    }
}
