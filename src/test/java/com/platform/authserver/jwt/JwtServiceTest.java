package com.platform.authserver.jwt;

import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;

import java.util.List;

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
    }
}
