package com.platform.authserver.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Date;
import java.util.List;

@Service
public class JwtService {

    private final JwtKeyProvider keyProvider;
    private final String issuer;
    private final long ttlSeconds;

    public JwtService(JwtKeyProvider keyProvider,
                      @Value("${platform.issuer}") String issuer,
                      @Value("${platform.access-token-ttl-seconds}") long ttlSeconds) {
        this.keyProvider = keyProvider;
        this.issuer = issuer;
        this.ttlSeconds = ttlSeconds;
    }

    public String issueAccessToken(long userId, String email, String name, List<String> roles, String provider) {
        Instant now = Instant.now();
        try {
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .issuer(issuer)
                    .subject(String.valueOf(userId))
                    .claim("email", email)
                    .claim("name", name)
                    .claim("provider", provider)
                    .claim("roles", roles)
                    .issueTime(Date.from(now))
                    .expirationTime(Date.from(now.plusSeconds(ttlSeconds)))
                    .build();

            SignedJWT jwt = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(keyProvider.keyId()).build(),
                    claims);
            jwt.sign(new RSASSASigner(keyProvider.rsaKey()));
            return jwt.serialize();
        } catch (JOSEException e) {
            throw new IllegalStateException("AT 발급 실패", e);
        }
    }
}
