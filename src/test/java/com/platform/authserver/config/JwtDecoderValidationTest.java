package com.platform.authserver.config;

import com.platform.authserver.jwt.JwtKeyProvider;
import com.platform.authserver.jwt.JwtService;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** /api/me 리소스서버 디코더가 서명뿐 아니라 issuer/audience까지 검증하는지. */
class JwtDecoderValidationTest {

    static final String ISSUER = "http://localhost:9000";
    static final String AUDIENCE = "platform-api";

    private final JwtKeyProvider keyProvider = new JwtKeyProvider(null);
    private final SecurityConfig config = new SecurityConfig();

    JwtDecoderValidationTest() throws Exception {
        keyProvider.init();
    }

    private String tokenFrom(String issuer, String audience) {
        return new JwtService(keyProvider, issuer, audience, 900)
                .issueAccessToken(1L, "a@demo.com", "A", List.of("USER"), "KEYCLOAK");
    }

    @Test
    void acceptsTokenWithExpectedIssuerAndAudience() throws Exception {
        JwtDecoder decoder = config.jwtDecoder(keyProvider, ISSUER, AUDIENCE);

        assertThat(decoder.decode(tokenFrom(ISSUER, AUDIENCE)).getSubject()).isEqualTo("1");
    }

    @Test
    void rejectsTokenFromDifferentIssuer() throws Exception {
        JwtDecoder decoder = config.jwtDecoder(keyProvider, ISSUER, AUDIENCE);

        assertThatThrownBy(() -> decoder.decode(tokenFrom("http://evil:9999", AUDIENCE)))
                .isInstanceOf(JwtException.class);
    }

    @Test
    void rejectsTokenWithWrongAudience() throws Exception {
        JwtDecoder decoder = config.jwtDecoder(keyProvider, ISSUER, AUDIENCE);

        assertThatThrownBy(() -> decoder.decode(tokenFrom(ISSUER, "other-api")))
                .isInstanceOf(JwtException.class);
    }
}
