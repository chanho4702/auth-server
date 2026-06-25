package com.platform.authserver.auth;

import org.springframework.security.oauth2.core.oidc.user.OidcUser;

import java.util.List;
import java.util.Map;

/** Keycloak OIDC 사용자 claim에서 플랫폼이 쓰는 값(roles/provider)을 뽑는다. */
public final class OidcClaims {

    private OidcClaims() {
    }

    @SuppressWarnings("unchecked")
    public static List<String> roles(OidcUser user) {
        Object realmAccess = user.getClaims().get("realm_access");
        if (realmAccess instanceof Map<?, ?> map && map.get("roles") instanceof List<?> roles) {
            return roles.stream().map(String::valueOf).toList();
        }
        return List.of();
    }

    /** Keycloak이 브로커링하면 identity_provider claim에 "google" 등이 담긴다. 없으면 KEYCLOAK. */
    public static String provider(OidcUser user) {
        Object idp = user.getClaims().get("identity_provider");
        if (idp != null && !idp.toString().isBlank()) {
            return idp.toString().toUpperCase();
        }
        return "KEYCLOAK";
    }
}
