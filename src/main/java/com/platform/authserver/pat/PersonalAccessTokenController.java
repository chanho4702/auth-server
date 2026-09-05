package com.platform.authserver.pat;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * 개인 API 토큰 관리 — 세션 JWT 필요. 이 경로는 {@code SecurityConfig.apiChain}의
 * {@code securityMatcher}에 반드시 들어 있어야 한다. 빠지면 {@code webChain}의
 * {@code /api/auth/**} permitAll로 떨어져 익명 사용자에게 열린다(회귀 테스트로 고정).
 *
 * <p>오류 계약은 auth 경로 관례대로 기계 코드 {@code {"error":"..."}}다 — 한국어 문구 매핑은
 * 프론트가 한다.
 */
@RestController
@RequestMapping("/api/auth/tokens")
public class PersonalAccessTokenController {

    private static final String PAT_PROVIDER = "PAT";

    private final PersonalAccessTokenService tokenService;

    public PersonalAccessTokenController(PersonalAccessTokenService tokenService) {
        this.tokenService = tokenService;
    }

    public record CreateRequest(String label, Integer expiresInDays) {}

    /** 목록 응답. 원문도 해시도 나가지 않는다 — 식별은 {@code hint}로만. */
    public record TokenView(String id, String label, String hint,
                            Instant createdAt, Instant expiresAt, Instant lastUsedAt, Instant revokedAt) {
        static TokenView of(PersonalAccessToken t) {
            return new TokenView(t.getId().toString(), t.getLabel(), t.getTokenHint(),
                    t.getCreatedAt(), t.getExpiresAt(), t.getLastUsedAt(), t.getRevokedAt());
        }
    }

    /** 발급 응답 — {@code token}(원문)이 실리는 유일한 응답이다. */
    public record CreatedView(String id, String label, String hint,
                              Instant createdAt, Instant expiresAt, String token) {}

    @GetMapping
    public ResponseEntity<?> list(@AuthenticationPrincipal Jwt jwt) {
        ResponseEntity<?> rejected = rejectPatJwt(jwt);
        if (rejected != null) {
            return rejected;
        }
        List<TokenView> body = tokenService.list(userId(jwt)).stream().map(TokenView::of).toList();
        return ResponseEntity.ok(body);
    }

    @PostMapping
    public ResponseEntity<?> create(@AuthenticationPrincipal Jwt jwt, @RequestBody(required = false) CreateRequest request) {
        ResponseEntity<?> rejected = rejectPatJwt(jwt);
        if (rejected != null) {
            return rejected;
        }

        String label = request == null || request.label() == null ? null : request.label().trim();
        if (label == null || label.isEmpty() || label.length() > PersonalAccessTokenService.MAX_LABEL_LENGTH) {
            return error(HttpStatus.BAD_REQUEST, "label_required");
        }
        int expiresInDays = request.expiresInDays() == null
                ? PersonalAccessTokenService.DEFAULT_EXPIRY_DAYS
                : request.expiresInDays();
        if (expiresInDays < PersonalAccessTokenService.MIN_EXPIRY_DAYS
                || expiresInDays > PersonalAccessTokenService.MAX_EXPIRY_DAYS) {
            return error(HttpStatus.BAD_REQUEST, "invalid_expiry");
        }

        PersonalAccessTokenService.Created created = tokenService.create(userId(jwt), label, expiresInDays);
        PersonalAccessToken t = created.token();
        return ResponseEntity.status(HttpStatus.CREATED).body(new CreatedView(
                t.getId().toString(), t.getLabel(), t.getTokenHint(),
                t.getCreatedAt(), t.getExpiresAt(), created.rawToken()));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<?> revoke(@AuthenticationPrincipal Jwt jwt, @PathVariable String id) {
        ResponseEntity<?> rejected = rejectPatJwt(jwt);
        if (rejected != null) {
            return rejected;
        }
        UUID tokenId;
        try {
            tokenId = UUID.fromString(id);
        } catch (IllegalArgumentException e) {
            // 형식이 틀린 id도 "그런 토큰 없음"과 같은 응답 — 존재 여부를 추측할 단서를 주지 않는다.
            return error(HttpStatus.NOT_FOUND, "not_found");
        }
        tokenService.revoke(userId(jwt), tokenId);
        return ResponseEntity.noContent().build();
    }

    @ExceptionHandler(TokenNotFoundException.class)
    ResponseEntity<?> handleNotFound(TokenNotFoundException e) {
        return error(HttpStatus.NOT_FOUND, "not_found");
    }

    @ExceptionHandler(TokenLimitExceededException.class)
    ResponseEntity<?> handleLimit(TokenLimitExceededException e) {
        return error(HttpStatus.CONFLICT, "token_limit");
    }

    /**
     * PAT로 교환한 JWT({@code provider=PAT})로는 토큰 관리를 못 한다 — 토큰 하나가 새 토큰을
     * 무한히 낳는 것을 막는다. 관리 API는 사람이 로그인한 세션 JWT로만 쓴다.
     */
    private ResponseEntity<?> rejectPatJwt(Jwt jwt) {
        if (PAT_PROVIDER.equals(jwt.getClaimAsString("provider"))) {
            return error(HttpStatus.FORBIDDEN, "pat_cannot_manage_tokens");
        }
        return null;
    }

    private long userId(Jwt jwt) {
        return Long.parseLong(jwt.getSubject());
    }

    private ResponseEntity<?> error(HttpStatus status, String code) {
        return ResponseEntity.status(status).body(Map.of("error", code));
    }
}
