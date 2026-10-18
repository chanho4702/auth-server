package com.platform.authserver.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.annotation.Profile;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * 배포 프로필(docker·prod)에서 application.yml의 로컬 dev 기본 비밀값으로 뜨는 것을 막는다(P-20).
 *
 * <p>검사 대상: OIDC 클라이언트 시크릿 {@code platform-bff-secret}(realm-export 기본값과 같다 — 리포에 공개돼 있다),
 * DB 비밀번호 {@code keycloak}. 둘 다 "운영에서는 반드시 주입" 주석만 있고 강제가 없었다.
 *
 * <p>정책 {@code platform.security.default-secrets}(env {@code PLATFORM_DEFAULT_SECRETS_POLICY}):
 * {@code fail}(기본) — 기동 실패, {@code warn} — 경고 로그만(실값 주입 전 과도기용). 로컬·테스트 프로필에서는
 * 이 빈 자체가 없다.
 */
@Component
@Profile({"docker", "prod"})
public class DefaultSecretsGuard implements InitializingBean {

    private static final Logger log = LoggerFactory.getLogger(DefaultSecretsGuard.class);

    static final String OIDC_SECRET_KEY = "spring.security.oauth2.client.registration.keycloak.client-secret";
    static final String DB_PASSWORD_KEY = "spring.datasource.password";
    static final String DEFAULT_OIDC_SECRET = "platform-bff-secret";
    static final String DEFAULT_DB_PASSWORD = "keycloak";

    private final Environment env;

    public DefaultSecretsGuard(Environment env) {
        this.env = env;
    }

    @Override
    public void afterPropertiesSet() {
        List<String> violations = violations(env);
        if (violations.isEmpty()) return;
        String policy = env.getProperty("platform.security.default-secrets", "fail").trim().toLowerCase(Locale.ROOT);
        String message = "배포 프로필에서 기본 비밀값으로 기동하려 한다: " + String.join(", ", violations)
                + " — 실값을 주입하라(과도기에는 PLATFORM_DEFAULT_SECRETS_POLICY=warn).";
        if ("warn".equals(policy)) {
            log.warn(message);
            return;
        }
        throw new IllegalStateException(message);
    }

    /** 기본값 그대로인 항목 이름(값 자체는 담지 않는다). */
    static List<String> violations(Environment env) {
        List<String> found = new ArrayList<>();
        if (DEFAULT_OIDC_SECRET.equals(trimmed(env.getProperty(OIDC_SECRET_KEY)))) {
            found.add("OIDC_CLIENT_SECRET(" + OIDC_SECRET_KEY + ")");
        }
        if (DEFAULT_DB_PASSWORD.equals(trimmed(env.getProperty(DB_PASSWORD_KEY)))) {
            found.add("AUTH_DB_PASSWORD(" + DB_PASSWORD_KEY + ")");
        }
        return found;
    }

    private static String trimmed(String v) {
        return v == null ? null : v.trim();
    }
}
