package com.platform.authserver.agent;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.List;

/**
 * {@code /internal/**} 전용 게이트. 게이트웨이가 이 경로를 라우팅하지 않으므로(클러스터 내부만
 * 접근 가능) 여기서는 헤더(기본 {@code X-Internal-Secret})를 경로별 허용 값과 상수시간 비교한다
 * (N5 — 경로별 값은 {@code SecurityConfig}가 {@code platform.internal.*}에서 골라 준다). 허용 값은 콤마로 여러 개
 * ({@code 신,구} — 무중단 회전) 적을 수 있다. 허용 값이 하나도 없으면(미설정, trim 후에도) 헤더 값과 무관하게 무조건
 * 403 — 컨테이너 env에 시크릿을 안 넣은 채 배포돼도 발급 경로가 열리지 않는다(fail-closed, S10).
 *
 * <p>설정값과 헤더 값 모두 {@code trim()} 후 비교한다 — 게이트웨이의 {@code PatExchangeClient}가
 * 자기 쪽 시크릿 사본을 trim해서 보내므로, {@code .env}에 트레일링 스페이스가 섞이면(흔한 실수)
 * trim 없이는 모든 PAT 교환이 이유 없이 503으로 깨진다.
 *
 * <p><b>의도적으로 {@code @Component}가 아니다.</b> Boot는 {@link jakarta.servlet.Filter} 빈을
 * 발견하면 {@code FilterRegistrationBean}으로 자동으로 서블릿 컨테이너 레벨(url-mapping
 * {@code /*}, {@code LOWEST_PRECEDENCE})에도 등록한다 — Spring Security 체인과 별개로 매
 * 요청마다 한 번 더 도는 두 번째 필터가 생겨, 시크릿 미설정 운영 기본값에서 {@code /api/me},
 * {@code /api/auth/refresh}, JWKS, OAuth2 콜백 등 전체가 403이 되는 사고로 실측됐다(C1).
 * {@code SecurityConfig.internalChain}에서 {@code new}로 직접 생성해 이 체인에만 등록한다.
 */
public class InternalSecretFilter extends OncePerRequestFilter {

    private static final String DEFAULT_HEADER = "X-Internal-Secret";
    private static final String DEFAULT_MESSAGE = "내부 시크릿이 유효하지 않습니다";

    private final String header;
    /**
     * 허용 값 목록 — 설정값을 콤마로 나눠 항목마다 trim하고 빈 항목은 버린다(N5 회전: {@code 신,구}).
     * 생성 시점에 한 번만 만든다. 비어 있으면 fail-closed.
     */
    private final List<byte[]> secrets;
    private final String body;

    public InternalSecretFilter(String secret) {
        this(DEFAULT_HEADER, secret, DEFAULT_MESSAGE);
    }

    /**
     * 헤더명·문구를 바꾼 같은 게이트 — org-service가 부르는 {@code /internal/users/**}는 org 쪽 규약대로
     * {@code X-Internal-Token} + {@code ORG_INTERNAL_TOKEN}을 쓴다(P-02). 경로별로 다른 시크릿을 받으면
     * 한 시크릿이 유출돼도 다른 경로는 열리지 않는다(P-07 방향).
     *
     * <p>common-starter 0.17.0의 {@code com.platform.common.security.InternalTokenFilter}와 같은 규칙(trim·상수시간·
     * fail-closed·{@code {"error"}})이다. auth-server는 스타터를 쓰지 않아(JWT 발급자 자신) 이 사본을 유지한다.
     */
    public InternalSecretFilter(String header, String secret, String message) {
        this.header = header;
        this.secrets = parse(secret);
        this.body = "{\"error\":\"" + message + "\"}";
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String presented = request.getHeader(header);
        String trimmedHeader = presented == null ? null : presented.trim();
        if (!matches(trimmedHeader)) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType("application/json;charset=UTF-8");
            response.getWriter().write(body);
            return;
        }
        filterChain.doFilter(request, response);
    }

    /**
     * 콤마 구분 목록을 허용 값으로 — 항목마다 trim, 빈 항목 무시. common-starter {@code InternalTokenFilter}(0.18.0)와 같은 의미론.
     * 값 자체에 콤마를 쓸 수 없다는 제약이 생기지만, 내부 토큰은 우리가 생성하는 무작위 문자열(hex/base64url)이라 문제없다.
     */
    static List<byte[]> parse(String configured) {
        if (configured == null) return List.of();
        return Arrays.stream(configured.split(","))
                .map(String::trim)
                .filter(v -> !v.isEmpty())
                .map(v -> v.getBytes(StandardCharsets.UTF_8))
                .toList();
    }

    /** 후보마다 상수시간 비교. 일치를 찾아도 멈추지 않는다 — 몇 번째 후보와 맞았는지가 응답 시간으로 새지 않게. */
    private boolean matches(String presented) {
        if (secrets.isEmpty() || presented == null || presented.isEmpty()) return false;
        byte[] candidate = presented.getBytes(StandardCharsets.UTF_8);
        boolean matched = false;
        for (byte[] allowed : secrets) {
            matched |= MessageDigest.isEqual(allowed, candidate);
        }
        return matched;
    }
}
