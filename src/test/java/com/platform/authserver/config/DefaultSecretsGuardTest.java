package com.platform.authserver.config;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;

/** P-20 — 배포 프로필에서 공개된 기본 비밀값(platform-bff-secret, keycloak)으로 뜨지 않는다. */
class DefaultSecretsGuardTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withUserConfiguration(DefaultSecretsGuard.class);

    private static final String OIDC = DefaultSecretsGuard.OIDC_SECRET_KEY + "=";
    private static final String DB = DefaultSecretsGuard.DB_PASSWORD_KEY + "=";

    @Test
    void docker_프로필에서_OIDC_시크릿이_기본값이면_기동이_실패한다() {
        runner.withPropertyValues("spring.profiles.active=docker", OIDC + "platform-bff-secret", DB + "s3cure")
                .run(ctx -> {
                    assertThat(ctx).hasFailed();
                    assertThat(ctx.getStartupFailure()).rootCause()
                            .hasMessageContaining("OIDC_CLIENT_SECRET")
                            .hasMessageNotContaining("platform-bff-secret"); // 값 자체는 로그에 남기지 않는다
                });
    }

    @Test
    void docker_프로필에서_DB_비밀번호가_기본값이면_기동이_실패한다() {
        runner.withPropertyValues("spring.profiles.active=docker", OIDC + "real-secret", DB + "keycloak")
                .run(ctx -> {
                    assertThat(ctx).hasFailed();
                    assertThat(ctx.getStartupFailure()).rootCause().hasMessageContaining("AUTH_DB_PASSWORD");
                });
    }

    @Test
    void prod_프로필도_같다() {
        runner.withPropertyValues("spring.profiles.active=prod", OIDC + "platform-bff-secret", DB + "s3cure")
                .run(ctx -> assertThat(ctx).hasFailed());
    }

    @Test
    void 실값이면_뜬다() {
        runner.withPropertyValues("spring.profiles.active=docker", OIDC + "real-secret", DB + "s3cure")
                .run(ctx -> assertThat(ctx).hasNotFailed().hasSingleBean(DefaultSecretsGuard.class));
    }

    @Test
    void warn_정책이면_경고만_하고_뜬다() {
        runner.withPropertyValues("spring.profiles.active=docker", OIDC + "platform-bff-secret", DB + "keycloak",
                        "platform.security.default-secrets=warn")
                .run(ctx -> assertThat(ctx).hasNotFailed());
    }

    @Test
    void 로컬_프로필에서는_검사하지_않는다() {
        runner.withPropertyValues(OIDC + "platform-bff-secret", DB + "keycloak")
                .run(ctx -> assertThat(ctx).hasNotFailed().doesNotHaveBean(DefaultSecretsGuard.class));
        runner.withPropertyValues("spring.profiles.active=dev", OIDC + "platform-bff-secret", DB + "keycloak")
                .run(ctx -> assertThat(ctx).hasNotFailed().doesNotHaveBean(DefaultSecretsGuard.class));
    }
}
