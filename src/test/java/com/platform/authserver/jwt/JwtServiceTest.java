package com.platform.authserver.jwt;

import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class JwtServiceTest {

    private final JwtKeyProvider keyProvider = new JwtKeyProvider(null);
    private final JwtService jwtService = new JwtService(keyProvider, "http://localhost:9000", "platform-api", 900);

    JwtServiceTest() throws Exception {
        keyProvider.init();
    }

    @Test
    void issuesVerifiableRs256TokenWithExpectedClaims() throws Exception {
        String token = jwtService.issueAccessToken(42L, "alice@demo.com", "Alice", List.of("USER", "ADMIN"), "GOOGLE");

        SignedJWT jwt = SignedJWT.parse(token);
        JWSVerifier verifier = new RSASSAVerifier(keyProvider.publicKey());

        assertThat(jwt.verify(verifier)).isTrue();
        assertThat(jwt.getHeader().getKeyID()).isEqualTo(keyProvider.keyId());
        assertThat(jwt.getJWTClaimsSet().getIssuer()).isEqualTo("http://localhost:9000");
        assertThat(jwt.getJWTClaimsSet().getAudience()).containsExactly("platform-api");
        assertThat(jwt.getJWTClaimsSet().getSubject()).isEqualTo("42");
        assertThat(jwt.getJWTClaimsSet().getStringClaim("email")).isEqualTo("alice@demo.com");
        assertThat(jwt.getJWTClaimsSet().getStringClaim("name")).isEqualTo("Alice");
        assertThat(jwt.getJWTClaimsSet().getStringClaim("provider")).isEqualTo("GOOGLE");
        assertThat(jwt.getJWTClaimsSet().getStringListClaim("roles")).containsExactly("USER", "ADMIN");
        assertThat(jwt.getJWTClaimsSet().getExpirationTime()).isAfter(new java.util.Date());
        // 세션 JWT에는 스코프가 없다 — scope 클레임은 PAT 교환 토큰에만 실린다.
        assertThat(jwt.getJWTClaimsSet().getClaim("scope")).isNull();
    }

    @Test
    void extraClaimsOverloadAddsScopeWithoutTouchingTheStandardClaims() throws Exception {
        String token = jwtService.issueAccessToken(42L, "alice@demo.com", "Alice", List.of("USER"), "PAT", 300,
                Map.of("scope", List.of("wiki:read", "alm:write")));

        SignedJWT jwt = SignedJWT.parse(token);
        assertThat(jwt.verify(new RSASSAVerifier(keyProvider.publicKey()))).isTrue();
        assertThat(jwt.getJWTClaimsSet().getStringListClaim("scope"))
                .containsExactly("wiki:read", "alm:write");
        assertThat(jwt.getJWTClaimsSet().getStringClaim("provider")).isEqualTo("PAT");
        assertThat(jwt.getJWTClaimsSet().getStringListClaim("roles")).containsExactly("USER");
        long ttl = (jwt.getJWTClaimsSet().getExpirationTime().getTime()
                - jwt.getJWTClaimsSet().getIssueTime().getTime()) / 1000;
        assertThat(ttl).isEqualTo(300);
    }
}
