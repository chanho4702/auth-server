package com.platform.authserver.agent;

import com.platform.authserver.invite.OrgInternalClient;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 에이전트 페르소나 관리({@code /api/auth/agents/**}) 게이트 — <b>org 활성 전역 관리자만</b>(2026-10-24).
 *
 * <p>예전에는 Keycloak realm 롤 ADMIN({@code hasRole("ADMIN")})이었다. 플랫폼 관리자의 정본은 org GLOBAL ADMIN grant이고
 * board·agent-service·wiki·alm이 같은 기준으로 옮겼으므로 여기도 맞춘다 — KC 롤만 가진 사람(예: 데모 계정 {@code admin})이
 * 페르소나를 만들어 서비스 토큰까지 이어지는 길을 닫는다.
 *
 * <p>판정: ADMIN → 통과, NOT_ADMIN → 403(본문 없음 — 예전 hasRole 거부와 같은 모양), UNAVAILABLE(org 장애·미설정) →
 * 503 {@code {"error":"org_unavailable"}}(거부로 위장하지 않는다). 확정 결과는 30초 캐시 — 회수 지연 최대 30초.
 *
 * <p>인증 전(익명) 요청은 건드리지 않는다 — 뒤의 AuthorizationFilter가 401을 낸다. PAT JWT는 앞의 {@code PatJwtGuardFilter}가
 * 먼저 끊는다. {@code InternalSecretFilter}와 같은 이유로 빈이 아니라 {@code new}로 만든다.
 */
public class OrgGlobalAdminFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(OrgGlobalAdminFilter.class);
    static final String PATH = "/api/auth/agents";

    private record Cached(OrgInternalClient.AdminCheck check, Instant at) {}

    private final OrgInternalClient org;
    private final Duration ttl;
    private final Clock clock;
    private final Map<Long, Cached> cache = new ConcurrentHashMap<>();

    public OrgGlobalAdminFilter(OrgInternalClient org) {
        this(org, Duration.ofSeconds(30), Clock.systemUTC());
    }

    OrgGlobalAdminFilter(OrgInternalClient org, Duration ttl, Clock clock) {
        this.org = org;
        this.ttl = ttl;
        this.clock = clock;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        String ctx = request.getContextPath();
        if (ctx != null && !ctx.isEmpty() && path.startsWith(ctx)) path = path.substring(ctx.length());
        return !(path.equals(PATH) || path.startsWith(PATH + "/"));
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (!(auth instanceof JwtAuthenticationToken jwt)) {
            chain.doFilter(request, response); // 익명 → AuthorizationFilter가 401
            return;
        }
        long userId;
        try {
            userId = Long.parseLong(jwt.getToken().getSubject());
        } catch (NumberFormatException e) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            return;
        }
        switch (check(userId)) {
            case ADMIN -> chain.doFilter(request, response);
            case NOT_ADMIN -> response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            case UNAVAILABLE -> {
                log.error("org 전역 관리자 판정 불가 — 에이전트 관리 요청 503: userId={}", userId);
                response.setStatus(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
                response.setContentType("application/json;charset=UTF-8");
                response.getWriter().write("{\"error\":\"org_unavailable\"}");
            }
        }
    }

    private OrgInternalClient.AdminCheck check(long userId) {
        Instant now = clock.instant();
        Cached hit = cache.get(userId);
        if (hit != null && hit.at().plus(ttl).isAfter(now)) return hit.check();
        OrgInternalClient.AdminCheck fresh = org.globalAdmin(userId);
        if (fresh != OrgInternalClient.AdminCheck.UNAVAILABLE) cache.put(userId, new Cached(fresh, now));
        return fresh;
    }
}
