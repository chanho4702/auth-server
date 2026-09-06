package com.platform.authserver.pat;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** 스코프 허용 집합·정규화 규칙과, V5 백필 문자열이 그 집합과 어긋나지 않는지. */
class PatScopesTest {

    @Test
    void allowed_set_is_exactly_the_seven_documented_scopes() {
        assertThat(PatScopes.ALL).containsExactly(
                "admin", "alm:read", "alm:write", "org:read", "org:write", "wiki:read", "wiki:write");
        assertThat(PatScopes.ALL).allMatch(PatScopes::isAllowed);
        assertThat(PatScopes.isAllowed("wiki:admin")).isFalse();
        assertThat(PatScopes.isAllowed("WIKI:READ")).isFalse(); // 대소문자 관용 없음
        assertThat(PatScopes.isAllowed(null)).isFalse();
    }

    @Test
    void normalize_trims_dedupes_and_sorts() {
        assertThat(PatScopes.normalize(Arrays.asList(" wiki:write ", "admin", "wiki:write", "alm:read")))
                .containsExactly("admin", "alm:read", "wiki:write");

        // 입력 순서가 달라도 저장·클레임 값은 같다.
        assertThat(PatScopes.normalize(List.of("alm:read", "admin")))
                .isEqualTo(PatScopes.normalize(List.of("admin", "alm:read")));
    }

    @Test
    void normalize_rejects_empty_and_unknown() {
        for (List<String> bad : List.of(List.<String>of(), List.of("   "))) {
            assertThatThrownBy(() -> PatScopes.normalize(bad)).isInstanceOf(IllegalArgumentException.class);
        }
        assertThatThrownBy(() -> PatScopes.normalize(Arrays.asList((String) null)))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> PatScopes.normalize(null)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> PatScopes.normalize(List.of("wiki:read", "wiki:delete")))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void clean_does_not_validate_so_the_controller_can_tell_empty_from_unknown() {
        assertThat(PatScopes.clean(null)).isEmpty();
        assertThat(PatScopes.clean(List.of(" ", ""))).isEmpty();
        assertThat(PatScopes.clean(List.of("nope"))).containsExactly("nope");
        assertThat(PatScopes.allAllowed(List.of("nope"))).isFalse();
        assertThat(PatScopes.allAllowed(List.of())).isFalse();
    }

    @Test
    void join_and_parse_round_trip() {
        String stored = PatScopes.join(PatScopes.ALL);
        assertThat(stored).isEqualTo("admin,alm:read,alm:write,org:read,org:write,wiki:read,wiki:write");
        assertThat(stored.length()).isLessThanOrEqualTo(255); // 컬럼 폭
        assertThat(PatScopes.parse(stored)).isEqualTo(PatScopes.ALL);
        assertThat(PatScopes.parse(null)).isEmpty();
        assertThat(PatScopes.parse("")).isEmpty();
    }

    /**
     * V5는 기존 행을 전체 스코프로 백필한다. 허용 집합에 스코프를 추가·삭제하면서 이 문자열을
     * 잊으면 기존 토큰의 권한이 조용히 어긋나므로 여기서 대조한다(마이그레이션은 수정 불가라
     * 어긋나면 새 마이그레이션이 필요하다는 신호다).
     */
    @Test
    void v5_backfill_matches_the_allowed_set() throws IOException {
        String sql;
        try (InputStream in = getClass().getClassLoader().getResourceAsStream("db/migration/V5__pat_scopes.sql")) {
            assertThat(in).isNotNull();
            sql = new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
        assertThat(sql).contains("'" + PatScopes.join(PatScopes.ALL) + "'");
        assertThat(sql).contains("SET NOT NULL");
    }
}
