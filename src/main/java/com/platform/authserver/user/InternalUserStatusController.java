package com.platform.authserver.user;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * 계정 상태 내부 API(P-02) — org-service의 구성원 상태 동기화 워커만 부른다.
 *
 * <p>{@code PUT /internal/users/{id}/status {"active": false}} → 계정을 닫는다(리프레시 토큰 전부 폐기, PAT 교환 거부).
 * {@code {"active": true}} → 다시 연다. 멱등. 응답: 204, 사용자 없음 404, {@code active} 누락 400.
 *
 * <p>인증은 {@code SecurityConfig.orgInternalChain}이 {@code X-Internal-Token}(= {@code ORG_INTERNAL_TOKEN})으로 한다.
 * 게이트웨이·nginx는 {@code /internal/**}을 라우팅하지 않는다.
 */
@RestController
public class InternalUserStatusController {

    private final UserService users;

    public InternalUserStatusController(UserService users) {
        this.users = users;
    }

    public record StatusRequest(Boolean active) {}

    @PutMapping("/internal/users/{id}/status")
    public ResponseEntity<?> setStatus(@PathVariable("id") long id, @RequestBody(required = false) StatusRequest request) {
        if (request == null || request.active() == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "active 값이 필요합니다"));
        }
        if (!users.setActive(id, request.active())) {
            return ResponseEntity.status(404).body(Map.of("error", "사용자를 찾을 수 없습니다"));
        }
        return ResponseEntity.noContent().build();
    }
}
