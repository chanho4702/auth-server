package com.platform.authserver.pat;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * PAT 교환으로 발급된 JWT({@code provider=PAT})가 <b>자기 증식 경로</b>를 못 타게 막는다.
 * 토큰 하나로 새 토큰을 무한히 찍어내거나, 토큰으로 에이전트 페르소나를 만들어 그 페르소나의
 * 서비스 토큰을 받아내는 우회를 차단한다. 두 경로 모두 사람이 로그인한 세션 JWT로만 쓴다.
 *
 * <p>막는 경로:
 * <ul>
 *   <li>{@code /api/auth/tokens/**} — 개인 API 토큰 발급·목록·폐기</li>
 *   <li>{@code /api/auth/agents/**} — 에이전트 페르소나 생성(그 페르소나는 서비스 토큰을 받는다)</li>
 * </ul>
 *
 * <p><b>컨트롤러가 아니라 체인에서 막는 이유:</b> 컨트롤러마다 검사를 복붙하면 새 엔드포인트를
 * 추가할 때 조용히 빠진다. 여기 한 곳에 경로를 모아 두면 그 경로 아래 무엇이 생기든 자동으로
 * 덮인다. {@code /api/me}처럼 PAT가 정당하게 쓰여야 하는 경로는 목록에 없으므로 영향이 없다.
 *
 * <p><b>의도적으로 {@code @Component}가 아니다.</b> Boot는 {@link jakarta.servlet.Filter} 빈을
 * 서블릿 컨테이너 레벨({@code /*})에도 자동 등록하기 때문에, 빈으로 두면 이 필터가 전 경로에서
 * 한 번 더 돌아 PAT JWT의 정상 요청까지 403이 된다(C1과 같은 사고). {@code SecurityConfig.apiChain}
 * 에서 {@code new}로 만들어 그 체인에만 등록한다.
 */
public class PatJwtGuardFilter extends OncePerRequestFilter {

    /** PAT JWT를 거부할 경로 프리픽스. 정확히 일치하거나 그 하위 경로면 막는다. */
    private static final String[] GUARDED_PREFIXES = {"/api/auth/tokens", "/api/auth/agents"};

    static final String PAT_PROVIDER = "PAT";
    /** 관리 경로와 에이전트 경로가 같은 코드를 쓴다 — 프론트가 한 갈래로 매핑한다. */
    static final String ERROR_CODE = "pat_cannot_manage_tokens";

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        if (isGuarded(pathWithinApplication(request)) && isPatJwt(SecurityContextHolder.getContext().getAuthentication())) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType("application/json;charset=UTF-8");
            response.getWriter().write("{\"error\":\"" + ERROR_CODE + "\"}");
            return;
        }
        filterChain.doFilter(request, response);
    }

    private static String pathWithinApplication(HttpServletRequest request) {
        String uri = request.getRequestURI();
        String contextPath = request.getContextPath();
        if (contextPath != null && !contextPath.isEmpty() && uri.startsWith(contextPath)) {
            return uri.substring(contextPath.length());
        }
        return uri;
    }

    private static boolean isGuarded(String path) {
        for (String prefix : GUARDED_PREFIXES) {
            // "/api/auth/tokensXYZ" 같은 유사 경로까지 잡지 않도록 경계를 정확히 본다.
            if (path.equals(prefix) || path.startsWith(prefix + "/")) {
                return true;
            }
        }
        return false;
    }

    private static boolean isPatJwt(Authentication authentication) {
        return authentication instanceof JwtAuthenticationToken jwtAuth
                && PAT_PROVIDER.equals(jwtAuth.getToken().getClaimAsString("provider"));
    }
}
