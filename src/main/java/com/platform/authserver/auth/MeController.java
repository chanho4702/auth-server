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

    /** 자체 AT claim을 프론트 AppUser 형태({email,name,provider,sub,role})로 반환. */
    @GetMapping("/me")
    public Map<String, Object> me(@AuthenticationPrincipal Jwt jwt) {
        List<String> roles = jwt.getClaimAsStringList("roles");
        Map<String, Object> body = new HashMap<>();
        body.put("sub", jwt.getSubject());
        body.put("email", jwt.getClaimAsString("email"));
        body.put("name", jwt.getClaimAsString("name"));
        body.put("provider", jwt.getClaimAsString("provider"));
        body.put("role", (roles == null || roles.isEmpty()) ? null : roles.get(0));
        return body;
    }
}
