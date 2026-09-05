package com.platform.authserver.agent;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * 관리자 전용 에이전트 페르소나 사용자 생성. 경로 자체는 일반 리소스서버 체인
 * (`SecurityConfig.apiChain`)이 ROLE_ADMIN으로 게이트한다 — 게이트웨이가 라우팅하는
 * 공개 대상 API다({@code /internal/**}과 다름).
 */
@RestController
@RequestMapping("/api/auth")
public class AgentAdminController {

    private static final Pattern SLUG_PATTERN = Pattern.compile("[a-z0-9-]{2,40}");

    private final AgentUserService agentUserService;

    public AgentAdminController(AgentUserService agentUserService) {
        this.agentUserService = agentUserService;
    }

    public record CreateAgentRequest(String slug, String name, String email) {}

    @PostMapping("/agents")
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
