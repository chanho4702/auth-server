package com.platform.authserver.pat;

import com.platform.authserver.agent.InternalSecretFilter;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * PAT → 플랫폼 JWT 교환. 게이트웨이의 PAT 필터만 호출하는 클러스터 내부 전용 경로다 —
 * 게이트웨이가 {@code /internal/**}을 라우팅하지 않고 nginx도 보내지 않는다. 인증은
 * {@link InternalSecretFilter}가 {@code SecurityConfig.internalChain}에서 전담하므로,
 * 이 컨트롤러에 도달했다는 것 자체가 시크릿 검증을 통과했다는 뜻이다.
 */
@RestController
@RequestMapping("/internal/pat")
public class PatExchangeController {

    private final PersonalAccessTokenService tokenService;

    public PatExchangeController(PersonalAccessTokenService tokenService) {
        this.tokenService = tokenService;
    }

    public record ExchangeRequest(String token) {}

    @PostMapping("/exchange")
    public ResponseEntity<?> exchange(@RequestBody(required = false) ExchangeRequest request) {
        String raw = request == null ? null : request.token();
        return tokenService.exchange(raw)
                .<ResponseEntity<?>>map(result -> ResponseEntity.ok(Map.of(
                        "accessToken", result.accessToken(),
                        "expiresInSeconds", result.expiresInSeconds())))
                // 없음·만료·폐기·사용자 비활성 전부 같은 401 — 구분은 서비스 로그에만.
                .orElseGet(() -> ResponseEntity.status(401).body(Map.of("error", "invalid_token")));
    }
}
