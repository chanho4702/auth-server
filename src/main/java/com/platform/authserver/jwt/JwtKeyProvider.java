package com.platform.authserver.jwt;

import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

/**
 * 자체 JWT 서명용 RSA 키. dev: keyPath 파일이 있으면 로드, 없으면 생성 후 저장(재시작해도
 * 발급한 토큰이 유효하도록 키를 고정). keyPath 가 null 이면 메모리에만 생성(테스트용).
 */
@Component
public class JwtKeyProvider {

    private final String keyPath;
    private RSAKey rsaKey;

    public JwtKeyProvider(
            @org.springframework.beans.factory.annotation.Value("${platform.jwk-path:./auth-jwk.json}") String keyPath) {
        this.keyPath = keyPath;
    }

    @PostConstruct
    public void init() throws Exception {
        if (keyPath != null) {
            Path path = Path.of(keyPath);
            if (Files.exists(path)) {
                this.rsaKey = RSAKey.parse(Files.readString(path));
                return;
            }
        }
        this.rsaKey = new RSAKeyGenerator(2048)
                .keyID(UUID.randomUUID().toString())
                .generate();
        if (keyPath != null) {
            persist(Path.of(keyPath));
        }
    }

    private void persist(Path path) throws IOException {
        Files.writeString(path, rsaKey.toJSONString());
    }

    public RSAKey rsaKey() {
        return rsaKey;
    }

    public RSAPublicKey publicKey() throws Exception {
        return rsaKey.toRSAPublicKey();
    }

    public String keyId() {
        return rsaKey.getKeyID();
    }
}
