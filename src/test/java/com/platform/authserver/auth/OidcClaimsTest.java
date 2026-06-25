package com.platform.authserver.auth;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class OidcClaimsTest {

    private OidcUser userWith(Map<String, Object> claims) {
        OidcIdToken idToken = new OidcIdToken(
                "tok", Instant.now(), Instant.now().plusSeconds(60),
                Map.of("sub", "kc-1", "email", "a@b.com", "name", "Alice",
                        "realm_access", Map.of("roles", List.of("USER", "ADMIN")),
                        "identity_provider", "google"));
        return new DefaultOidcUser(List.of(), idToken);
    }

    @Test
    void extractsRealmRoles() {
        OidcUser user = userWith(Map.of());
        assertThat(OidcClaims.roles(user)).containsExactlyInAnyOrder("USER", "ADMIN");
    }

    @Test
    void mapsIdentityProvider() {
        OidcUser user = userWith(Map.of());
        assertThat(OidcClaims.provider(user)).isEqualTo("GOOGLE");
    }
}
