package com.platform.authserver.auth;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class MeController {

    /**
     * 자체 AT claim을 프론트 AppUser 형태로 반환.
     *
     * <p>{@code role}(첫 역할 하나)은 그대로 두고 {@code roles}(전체 배열)를 더한다 — 기존 화면이
     * {@code role} 하나를 읽고 있어 바꾸면 깨진다. <b>전역 관리자 판정은 여기가 아니다</b>:
     * 그것은 {@code GET /api/org/me}의 {@code globalRoles}이고, auth-server는 org를 모른다.
     * 여기 {@code roles}는 Keycloak realm 역할이다.
     */
    @GetMapping("/me")
    public Map<String, Object> me(@AuthenticationPrincipal Jwt jwt) {
        List<String> roles = jwt.getClaimAsStringList("roles");
        Map<String, Object> body = new HashMap<>();
        body.put("sub", jwt.getSubject());
        body.put("email", jwt.getClaimAsString("email"));
        body.put("name", jwt.getClaimAsString("name"));
        body.put("provider", jwt.getClaimAsString("provider"));
        body.put("role", (roles == null || roles.isEmpty()) ? null : roles.get(0));
        body.put("roles", roles == null ? List.of() : roles);
        return body;
    }
}
