package com.platform.authserver.pat;

import com.platform.authserver.TestOAuth2ClientConfig;
import com.platform.authserver.token.RefreshTokenService;
import com.platform.authserver.user.User;
import com.platform.authserver.user.UserRepository;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.TestPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 실 Postgres 검증 — H2 create-drop 스위트가 원리적으로 못 보는 것:
 * Flyway V4가 실제로 적용되는지, 그리고 그 스키마가 {@code ddl-auto=validate}를 통과하는지.
 * (컨텍스트가 뜬다는 사실 자체가 검증이다 — 앱도 운영에서 validate로 기동한다.)
 * test 프로필을 쓰지 않는다(프로필이 H2 + Flyway off 로 바꿔버린다).
 */
@Testcontainers
@SpringBootTest
@Import(TestOAuth2ClientConfig.class)
@TestPropertySource(properties = {"eureka.client.enabled=false"})
class PersonalAccessTokenPostgresTest {

    @Container
    @ServiceConnection
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:16");

    @Autowired PersonalAccessTokenRepository tokenRepository;
    @Autowired UserRepository userRepository;
    @Autowired PersonalAccessTokenService tokenService;
    @Autowired PatCleanupJob cleanupJob;
    @Autowired JdbcTemplate jdbc;

    @AfterEach
    void clean() {
        tokenRepository.deleteAll();
        userRepository.deleteAll();
    }

    private User newUser() {
        User u = new User("kc-pat-pg-" + System.nanoTime());
        u.setRoles(List.of("USER"));
        return userRepository.save(u);
    }

    private PersonalAccessToken persist(User owner, Instant expiresAt, Instant revokedAt) {
        String raw = PersonalAccessTokenService.TOKEN_PREFIX + UUID.randomUUID();
        PersonalAccessToken token = new PersonalAccessToken(owner.getId(), "라벨",
                RefreshTokenService.sha256(raw), raw.substring(raw.length() - 4), Instant.now(), expiresAt);
        if (revokedAt != null) {
            token.revoke(revokedAt);
        }
        return tokenRepository.save(token);
    }

    @Test
    void v4_migration_creates_the_table_with_its_indexes() {
        Integer table = jdbc.queryForObject(
                "SELECT COUNT(*) FROM information_schema.tables WHERE table_name = 'personal_access_tokens'",
                Integer.class);
        assertThat(table).isEqualTo(1);

        List<String> indexes = jdbc.queryForList(
                "SELECT indexdef FROM pg_indexes WHERE tablename = 'personal_access_tokens'", String.class);
        assertThat(indexes).anyMatch(def -> def.contains("(user_id)"));
        assertThat(indexes).anyMatch(def -> def.contains("UNIQUE") && def.contains("(token_hash)"));
    }

    @Test
    void entity_round_trips_against_the_migrated_schema() {
        User user = newUser();
        PersonalAccessTokenService.Created created = tokenService.create(user.getId(), "CI 배포", 30);

        PersonalAccessToken reloaded = tokenRepository
                .findByTokenHash(RefreshTokenService.sha256(created.rawToken())).orElseThrow();
        assertThat(reloaded.getLabel()).isEqualTo("CI 배포");
        assertThat(reloaded.getUserId()).isEqualTo(user.getId());
        assertThat(reloaded.getTokenHint()).isEqualTo(created.rawToken().substring(created.rawToken().length() - 4));
        assertThat(reloaded.getExpiresAt()).isAfter(Instant.now().plus(29, ChronoUnit.DAYS));
        assertThat(reloaded.getLastUsedAt()).isNull();
        assertThat(reloaded.getRevokedAt()).isNull();
    }

    @Test
    void cleanup_deletes_only_tokens_stale_for_the_retention_period() {
        User user = newUser();
        Instant now = Instant.now();

        PersonalAccessToken active = persist(user, now.plus(30, ChronoUnit.DAYS), null);
        PersonalAccessToken recentlyRevoked = persist(user, now.plus(30, ChronoUnit.DAYS), now.minus(3, ChronoUnit.DAYS));
        PersonalAccessToken recentlyExpired = persist(user, now.minus(3, ChronoUnit.DAYS), null);
        PersonalAccessToken longRevoked = persist(user, now.plus(30, ChronoUnit.DAYS), now.minus(120, ChronoUnit.DAYS));
        PersonalAccessToken longExpired = persist(user, now.minus(120, ChronoUnit.DAYS), null);

        cleanupJob.cleanup();

        assertThat(tokenRepository.findAllById(List.of(
                active.getId(), recentlyRevoked.getId(), recentlyExpired.getId())))
                .hasSize(3);
        assertThat(tokenRepository.findById(longRevoked.getId())).isEmpty();
        assertThat(tokenRepository.findById(longExpired.getId())).isEmpty();
    }
}
