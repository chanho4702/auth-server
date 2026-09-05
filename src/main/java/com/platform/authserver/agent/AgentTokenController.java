package com.platform.authserver.agent;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * 클러스터 내부 전용 — 게이트웨이가 {@code /internal/**}을 라우팅하지 않는다(S10). 인증은
 * {@link InternalSecretFilter}가 {@code SecurityConfig.internalChain}에서 전담하므로 이
 * 컨트롤러에 도달했다는 것 자체가 이미 시크릿 검증을 통과했다는 뜻이다.
 */
@RestController
@RequestMapping("/internal")
public class AgentTokenController {

    private final AgentUserService agentUserService;
    private final long ttlSeconds;

    public AgentTokenController(AgentUserService agentUserService,
                                 @Value("${platform.access-token-ttl-seconds}") long ttlSeconds) {
        this.agentUserService = agentUserService;
        this.ttlSeconds = ttlSeconds;
    }

    public record MintRequest(Long userId) {}

    @PostMapping("/service-tokens")
    public ResponseEntity<?> mint(@RequestBody MintRequest request) {
        if (request.userId() == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "userId가 필요합니다"));
        }
        return agentUserService.mint(request.userId())
                .<ResponseEntity<?>>map(token -> ResponseEntity.ok(Map.of(
                        "accessToken", token,
                        "expiresInSeconds", ttlSeconds)))
                .orElseGet(() -> ResponseEntity.status(403)
                        .body(Map.of("error", "에이전트 페르소나 사용자가 아닙니다")));
    }
}
