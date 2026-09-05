package com.platform.authserver.invite;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

import java.net.http.HttpClient;
import java.time.Duration;
import java.util.Map;
import java.util.Optional;

/**
 * org-service의 서비스 간 초대 API 클라이언트.
 *
 * <p>이 두 호출은 로그인 <b>도중</b>에 일어나 아직 우리 토큰이 없다 — 그래서 사용자 JWT가 아니라
 * {@code X-Internal-Token} 헤더로 인증하고, 게이트웨이가 라우팅하지 않는 {@code /internal/org/**}로 간다.
 *
 * <p>실패는 예외로 올리지 않는다. 초대 확인이 실패하면 그냥 평소 로그인으로 보내고, 수락 호출이 실패해도
 * 로그인은 계속한다 — 이메일 대조 경로가 남아 있고, org가 잠깐 안 뜬다고 로그인을 막을 이유가 없다.
 */
@Component
public class OrgInternalClient {

    private static final Logger log = LoggerFactory.getLogger(OrgInternalClient.class);

    private final RestClient restClient;
    private final String baseUri;
    private final String internalToken;

    public OrgInternalClient(@Value("${platform.org.service-uri:}") String baseUri,
                             @Value("${platform.org.internal-token:}") String internalToken) {
        this.baseUri = trimTrailingSlash(baseUri);
        this.internalToken = internalToken == null ? "" : internalToken;
        // org가 멈추면 로그인 스레드가 함께 잠긴다 — best-effort는 예외는 삼켜도 행(hang)은 못 삼킨다.
        HttpClient httpClient = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build();
        JdkClientHttpRequestFactory requestFactory = new JdkClientHttpRequestFactory(httpClient);
        requestFactory.setReadTimeout(Duration.ofSeconds(3));
        this.restClient = RestClient.builder().requestFactory(requestFactory).build();
    }

    public boolean isConfigured() { return !baseUri.isEmpty() && !internalToken.isEmpty(); }

    /** 초대 토큰의 이메일. 유효하지 않거나 org가 답하지 않으면 빈 값이다. */
    public Optional<InviteView> findInvite(String token) {
        if (!isConfigured()) return Optional.empty();
        try {
            Map<?, ?> body = restClient.get()
                    .uri(baseUri + "/internal/org/invitations/by-token/{token}", token)
                    .header("X-Internal-Token", internalToken)
                    .retrieve()
                    .body(Map.class);
            if (body == null) return Optional.empty();
            Object email = body.get("email");
            return email == null ? Optional.empty()
                    : Optional.of(new InviteView(String.valueOf(email), String.valueOf(body.get("status"))));
        } catch (RestClientException e) {
            // 토큰 값은 로그에 남기지 않는다 — 그 자체가 자격이다.
            log.debug("초대 토큰 확인 실패: {}", e.getClass().getSimpleName());
            return Optional.empty();
        }
    }

    /** 로그인 성공 직후의 수락 통보. 실패해도 로그인은 계속한다. */
    public void accept(String token, long memberId, String email, String displayName) {
        if (!isConfigured()) return;
        try {
            restClient.post()
                    .uri(baseUri + "/internal/org/invitations/accept")
                    .header("X-Internal-Token", internalToken)
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(Map.of(
                            "token", token,
                            "memberId", memberId,
                            "email", email == null ? "" : email,
                            "displayName", displayName == null ? "" : displayName))
                    .retrieve()
                    .toBodilessEntity();
        } catch (RestClientException e) {
            log.warn("초대 수락 통보 실패(로그인은 계속): {}", e.getClass().getSimpleName());
        }
    }

    private static String trimTrailingSlash(String value) {
        String v = value == null ? "" : value.trim();
        while (v.endsWith("/")) v = v.substring(0, v.length() - 1);
        return v;
    }

    /** 초대 링크가 가리키는 사람. {@code status}는 org가 준 문자열 그대로다. */
    public record InviteView(String email, String status) {}
}
