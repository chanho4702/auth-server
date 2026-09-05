package com.platform.authserver.agent;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * {@code /internal/**} 전용 게이트. 게이트웨이가 이 경로를 라우팅하지 않으므로(클러스터 내부만
 * 접근 가능) 여기서는 {@code X-Internal-Secret} 헤더를 {@code platform.agent.internal-secret}과
 * 상수시간 비교한다. 시크릿이 빈 문자열(미설정)이면 헤더 값과 무관하게 무조건 403 —
 * 컨테이너 env에 시크릿을 안 넣은 채 배포돼도 발급 경로가 열리지 않는다(fail-closed, S10).
 */
@Component
public class InternalSecretFilter extends OncePerRequestFilter {

    private static final String HEADER = "X-Internal-Secret";

    private final String secret;

    public InternalSecretFilter(@Value("${platform.agent.internal-secret:}") String secret) {
        this.secret = secret;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String header = request.getHeader(HEADER);
        boolean valid = !secret.isEmpty()
                && header != null
                && MessageDigest.isEqual(
                        secret.getBytes(StandardCharsets.UTF_8),
                        header.getBytes(StandardCharsets.UTF_8));
        if (!valid) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType("application/json;charset=UTF-8");
            response.getWriter().write("{\"error\":\"내부 시크릿이 유효하지 않습니다\"}");
            return;
        }
        filterChain.doFilter(request, response);
    }
}
