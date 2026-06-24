package com.platform.authserver.jwt;

import com.nimbusds.jose.jwk.JWKSet;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class JwksController {

    private final JwtKeyProvider keyProvider;

    public JwksController(JwtKeyProvider keyProvider) {
        this.keyProvider = keyProvider;
    }

    /** 공개키만 노출(toPublicJWK). 미래 서비스/게이트웨이가 이 URL로 자체 JWT를 검증한다. */
    @GetMapping("/.well-known/jwks.json")
    public Map<String, Object> jwks() {
        return new JWKSet(keyProvider.rsaKey().toPublicJWK()).toJSONObject();
    }
}
