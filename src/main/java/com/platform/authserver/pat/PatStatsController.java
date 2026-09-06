package com.platform.authserver.pat;

import com.platform.authserver.agent.InternalSecretFilter;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * PAT 집계 — 관리자 대시보드(게이트웨이 {@code /api/platform/stats/tokens})만 부르는
 * 클러스터 내부 경로다. 인증은 {@code /internal/pat/exchange}와 완전히 같은 배선이다:
 * {@code SecurityConfig.internalChain}의 {@link InternalSecretFilter}
 * ({@code X-Internal-Secret})가 전담하고, 이 컨트롤러에 도달했다는 것 자체가 통과했다는 뜻이다.
 *
 * <p>캐시는 여기 없다 — 게이트웨이가 60초 캐시한다(부하 원칙: 서비스는 COUNT만).
 */
@RestController
@RequestMapping("/internal/pat")
public class PatStatsController {

    private final PersonalAccessTokenService tokenService;

    public PatStatsController(PersonalAccessTokenService tokenService) {
        this.tokenService = tokenService;
    }

    @GetMapping("/stats")
    public ResponseEntity<PersonalAccessTokenService.Stats> stats() {
        return ResponseEntity.ok(tokenService.stats());
    }
}
