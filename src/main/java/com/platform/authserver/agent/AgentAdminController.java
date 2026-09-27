package com.platform.authserver.agent;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * 에이전트 페르소나 사용자 생성. 한 핸들러가 두 경로를 받으며 인증은 경로별 체인이 전담한다.
 * <ul>
 *   <li>{@code /api/auth/agents} — 일반 리소스서버 체인({@code SecurityConfig.apiChain})이
 *       ROLE_ADMIN으로 게이트. 게이트웨이가 라우팅하는 공개 대상 API.</li>
 *   <li>{@code /internal/agents} — {@code SecurityConfig.internalChain}의
 *       {@link InternalSecretFilter}가 {@code X-Internal-Secret}으로 게이트. 게이트웨이·nginx가
 *       {@code /internal/**}을 라우팅하지 않아 클러스터 내부(agent-service)에서만 닿는다 — 권한
 *       판정은 호출하는 쪽 책임(AGP-64).</li>
 * </ul>
 * 요청·응답 shape과 동작이 두 경로에서 같아야 하므로 핸들러를 나누지 않는다.
 */
@RestController
public class AgentAdminController {

    private static final Pattern SLUG_PATTERN = Pattern.compile("[a-z0-9-]{2,40}");

    private final AgentUserService agentUserService;

    public AgentAdminController(AgentUserService agentUserService) {
        this.agentUserService = agentUserService;
    }

    public record CreateAgentRequest(String slug, String name, String email) {}

    @PostMapping({"/api/auth/agents", "/internal/agents"})
    public ResponseEntity<?> createAgent(@RequestBody CreateAgentRequest request) {
        String slug = request.slug();
        if (slug == null || !SLUG_PATTERN.matcher(slug).matches()) {
            return ResponseEntity.badRequest()
                    .body(Map.of("error", "slug는 소문자/숫자/하이픈 2~40자여야 합니다"));
        }

        AgentUserService.AgentResult result = agentUserService.createOrGet(slug, request.name(), request.email());

        Map<String, Object> body = new HashMap<>();
        body.put("userId", result.userId());
        body.put("slug", result.slug());
        body.put("created", result.created());
        return ResponseEntity.ok(body);
    }
}
