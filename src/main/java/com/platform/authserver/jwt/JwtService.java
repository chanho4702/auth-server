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
import java.util.Map;

@Service
public class JwtService {

    private final JwtKeyProvider keyProvider;
    private final String issuer;
    private final String audience;
    private final long ttlSeconds;

    public JwtService(JwtKeyProvider keyProvider,
                      @Value("${platform.issuer}") String issuer,
                      @Value("${platform.audience}") String audience,
                      @Value("${platform.access-token-ttl-seconds}") long ttlSeconds) {
        this.keyProvider = keyProvider;
        this.issuer = issuer;
        this.audience = audience;
        this.ttlSeconds = ttlSeconds;
    }

    /** 기본 AT TTL({@code platform.access-token-ttl-seconds})로 발급. */
    public String issueAccessToken(long userId, String email, String name, List<String> roles, String provider) {
        return issueAccessToken(userId, email, name, roles, provider, ttlSeconds);
    }

    /**
     * TTL을 호출부가 정하는 오버로드. PAT 교환({@code provider="PAT"})은 세션 AT보다 짧은
     * TTL({@code platform.pat-jwt-ttl-seconds})을 쓴다 — 토큰 폐기 후 잔존 시간을 줄이기 위함.
     */
    public String issueAccessToken(long userId, String email, String name, List<String> roles, String provider,
                                   long ttlSeconds) {
        return issueAccessToken(userId, email, name, roles, provider, ttlSeconds, Map.of());
    }

    /**
     * 추가 클레임을 얹는 오버로드. PAT 교환이 {@code scope}(문자열 배열)를 이 경로로 넣는다 —
     * 세션 JWT에는 없는 클레임이라 표준 클레임 목록에 상수로 박지 않는다.
     *
     * <p>{@code extraClaims}는 표준 클레임 뒤에 적용되므로 {@code sub}/{@code roles} 같은 이름을
     * 넣으면 덮어쓴다. 호출부는 겹치지 않는 이름만 넘긴다.
     */
    public String issueAccessToken(long userId, String email, String name, List<String> roles, String provider,
                                   long ttlSeconds, Map<String, Object> extraClaims) {
        Instant now = Instant.now();
        try {
            JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                    .issuer(issuer)
                    .audience(audience)
                    .subject(String.valueOf(userId))
                    .claim("email", email)
                    .claim("name", name)
                    .claim("provider", provider)
                    .claim("roles", roles)
                    .issueTime(Date.from(now))
                    .expirationTime(Date.from(now.plusSeconds(ttlSeconds)));
            if (extraClaims != null) {
                extraClaims.forEach(builder::claim);
            }
            JWTClaimsSet claims = builder.build();

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
