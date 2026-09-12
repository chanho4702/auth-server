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
import org.flywaydb.core.Flyway;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.TestPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import javax.sql.DataSource;
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
    @Autowired DataSource dataSource;

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
                RefreshTokenService.sha256(raw), raw.substring(raw.length() - 4),
                List.of(PatScopes.WIKI_READ), Instant.now(), expiresAt);
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
        PersonalAccessTokenService.Created created = tokenService.create(
                user.getId(), "CI 배포", 30, List.of(PatScopes.WIKI_READ, PatScopes.ALM_READ));

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
    void v5_adds_a_not_null_scopes_column_that_the_entity_validates_against() {
        // ddl-auto=validate로 컨텍스트가 떴다는 것 자체가 매핑 일치의 증거고, 여기서는 제약을 못 박는다.
        String nullable = jdbc.queryForObject("""
                SELECT is_nullable FROM information_schema.columns
                 WHERE table_name = 'personal_access_tokens' AND column_name = 'scopes'
                """, String.class);
        assertThat(nullable).isEqualTo("NO");

        Integer length = jdbc.queryForObject("""
                SELECT character_maximum_length FROM information_schema.columns
                 WHERE table_name = 'personal_access_tokens' AND column_name = 'scopes'
                """, Integer.class);
        assertThat(length).isEqualTo(255);

        User user = newUser();
        PersonalAccessTokenService.Created created = tokenService.create(
                user.getId(), "스코프", 30, List.of(PatScopes.WIKI_WRITE, PatScopes.ADMIN));

        // 저장은 쉼표 구분 한 컬럼, 읽기는 정렬된 목록.
        String stored = jdbc.queryForObject("SELECT scopes FROM personal_access_tokens WHERE id = ?",
                String.class, created.token().getId());
        assertThat(stored).isEqualTo("admin,wiki:write");
        assertThat(tokenRepository.findById(created.token().getId()).orElseThrow().getScopes())
                .containsExactly("admin", "wiki:write");
    }

    /**
     * 스코프 개념 이전에 발급된 행이 V5→V6을 거쳐 전체 스코프가 되는지, 그리고 <b>스코프를 좁혀
     * 발급한 행은 V6이 건드리지 않는지</b> — 별도 스키마에 V4까지만 올린 뒤 두 행을 심고 나머지
     * 마이그레이션을 적용해 실제 백필을 돌린다. 앱이 쓰는 스키마(public)는 이미 최신이라 이
     * 경로를 재현할 수 없다.
     *
     * <p>좁은 행을 함께 검증하는 이유: V6이 조건 없이 UPDATE하면 사용자가 {@code wiki:read} 하나로
     * 발급한 토큰에 게시판 쓰기가 얹힌다. 마이그레이션은 되돌릴 수 없으므로 여기서 못 박는다.
     */
    @Test
    void v5_and_v6_backfill_legacy_rows_without_widening_narrow_ones() {
        String schema = "pat_backfill";
        UUID legacyId = UUID.randomUUID();
        UUID narrowId = UUID.randomUUID();
        try {
            flyway(schema).target("4").load().migrate();

            jdbc.update("INSERT INTO " + schema + ".users (keycloak_sub, roles, created_at) VALUES (?, ?, ?)",
                    "kc-legacy-" + System.nanoTime(), "USER", java.sql.Timestamp.from(Instant.now()));
            Long userId = jdbc.queryForObject("SELECT MAX(id) FROM " + schema + ".users", Long.class);
            seedToken(schema, userId, legacyId, "예전 토큰", null);

            // V5까지만 올려 legacy 행이 7개로 채워지게 한 뒤 좁은 행을 심는다 — "스코프를 골라
            // 발급한 토큰"을 V6 직전 상태로 재현하는 유일한 방법이다(V5 이후로는 컬럼이 NOT NULL).
            flyway(schema).target("5").load().migrate();
            assertThat(storedScopes(schema, legacyId)).containsExactly(
                    "admin", "alm:read", "alm:write", "org:read", "org:write", "wiki:read", "wiki:write");
            seedToken(schema, userId, narrowId, "좁은 토큰", PatScopes.WIKI_READ);

            flyway(schema).load().migrate();

            // 기존 토큰은 모든 경로에 쓰이고 있었으므로 전체 스코프 — 좁히면 돌던 스크립트가 깨진다.
            assertThat(storedScopes(schema, legacyId)).isEqualTo(PatScopes.ALL);
            // 사용자가 좁힌 토큰은 그대로. 게시판 쓰기가 얹히면 권한 확대다.
            assertThat(storedScopes(schema, narrowId)).containsExactly(PatScopes.WIKI_READ);
        } finally {
            // 남기면 information_schema를 스키마 없이 훑는 다른 테스트가 같은 테이블을 두 번 본다.
            jdbc.execute("DROP SCHEMA IF EXISTS " + schema + " CASCADE");
        }
    }

    private org.flywaydb.core.api.configuration.FluentConfiguration flyway(String schema) {
        return Flyway.configure()
                .dataSource(dataSource)
                .schemas(schema)
                .createSchemas(true)
                .locations("classpath:db/migration");
    }

    /** {@code scopes}가 null이면 컬럼을 빼고 넣는다 — V5 이전 스키마(컬럼 자체가 없음)를 재현한다. */
    private void seedToken(String schema, Long userId, UUID tokenId, String label, String scopes) {
        String columns = "(id, user_id, label, token_hash, token_hint, created_at, expires_at"
                + (scopes == null ? ")" : ", scopes)");
        String values = " VALUES (?, ?, ?, ?, ?, ?, ?" + (scopes == null ? ")" : ", ?)");
        Object[] args = scopes == null
                ? new Object[] {tokenId, userId, label, "hash-" + tokenId, "ab12",
                        java.sql.Timestamp.from(Instant.now()),
                        java.sql.Timestamp.from(Instant.now().plus(30, ChronoUnit.DAYS))}
                : new Object[] {tokenId, userId, label, "hash-" + tokenId, "ab12",
                        java.sql.Timestamp.from(Instant.now()),
                        java.sql.Timestamp.from(Instant.now().plus(30, ChronoUnit.DAYS)), scopes};
        jdbc.update("INSERT INTO " + schema + ".personal_access_tokens " + columns + values, args);
    }

    private List<String> storedScopes(String schema, UUID tokenId) {
        return PatScopes.parse(jdbc.queryForObject(
                "SELECT scopes FROM " + schema + ".personal_access_tokens WHERE id = ?", String.class, tokenId));
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
