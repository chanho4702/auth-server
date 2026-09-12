package com.platform.authserver.pat;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** 스코프 허용 집합·정규화 규칙과, V5+V6 백필 문자열이 그 집합과 어긋나지 않는지. */
class PatScopesTest {

    /** V5가 기존 행에 채운 문자열. V6은 정확히 이 값인 행만 골라 넓힌다. */
    private static final String V5_BACKFILL = "admin,alm:read,alm:write,org:read,org:write,wiki:read,wiki:write";

    @Test
    void allowed_set_is_exactly_the_ten_documented_scopes() {
        assertThat(PatScopes.ALL).containsExactly(
                "admin", "alm:read", "alm:write", "board:read", "board:write",
                "org:read", "org:write", "search:read", "wiki:read", "wiki:write");
        assertThat(PatScopes.ALL).allMatch(PatScopes::isAllowed);
        assertThat(PatScopes.isAllowed("wiki:admin")).isFalse();
        assertThat(PatScopes.isAllowed("WIKI:READ")).isFalse(); // 대소문자 관용 없음
        assertThat(PatScopes.isAllowed(null)).isFalse();
    }

    /** 검색은 읽기 전용 — 쓰기 스코프를 만들지 않았다(게이트웨이도 search:write를 요구하지 않는다). */
    @Test
    void search_has_no_write_scope() {
        assertThat(PatScopes.isAllowed("search:read")).isTrue();
        assertThat(PatScopes.isAllowed("search:write")).isFalse();
        assertThat(PatScopes.ALL).contains("board:read", "board:write").doesNotContain("search:write");
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
        assertThat(stored).isEqualTo("admin,alm:read,alm:write,board:read,board:write,"
                + "org:read,org:write,search:read,wiki:read,wiki:write");
        assertThat(stored.length()).isLessThanOrEqualTo(255); // 컬럼 폭
        assertThat(PatScopes.parse(stored)).isEqualTo(PatScopes.ALL);
        assertThat(PatScopes.parse(null)).isEmpty();
        assertThat(PatScopes.parse("")).isEmpty();
    }

    /**
     * V5는 당시의 전체 스코프(7개)로 기존 행을 백필했다. 적용된 마이그레이션은 수정할 수 없으므로
     * 이 문자열은 앞으로도 그대로다 — 허용 집합이 늘어나도 V5를 고치는 게 아니라 새 마이그레이션을
     * 얹는다는 사실을 여기서 고정한다.
     */
    @Test
    void v5_backfill_is_frozen_at_the_original_seven() throws IOException {
        String sql = migration("V5__pat_scopes.sql");
        assertThat(sql).contains("'" + V5_BACKFILL + "'");
        assertThat(sql).contains("SET NOT NULL");
    }

    /**
     * V6은 board·search를 더한다. 두 가지를 대조한다.
     *
     * <p>하나, 백필 결과 문자열이 현재 허용 집합 전체와 정확히 같은가 — 어긋나면 기존 토큰의
     * 권한이 조용히 실제 집합과 달라진다.
     *
     * <p>둘, 대상이 "V5 백필 값 그대로인 행"으로 한정되는가 — 스코프를 좁혀 발급한 토큰에
     * 게시판 쓰기가 얹히면 안 된다.
     */
    @Test
    void v6_backfill_widens_only_the_v5_rows_and_lands_on_the_full_set() throws IOException {
        String sql = migration("V6__pat_scopes_board_search.sql");
        assertThat(sql).contains("SET scopes = '" + PatScopes.join(PatScopes.ALL) + "'");
        assertThat(sql).contains("WHERE scopes = '" + V5_BACKFILL + "'");
    }

    /** V5 백필 + V6이 덧붙이는 값 = 현재 허용 집합. 셋 중 하나만 손대면 여기서 걸린다. */
    @Test
    void v5_and_v6_backfills_add_up_to_the_allowed_set() {
        List<String> cumulative = new ArrayList<>(PatScopes.parse(V5_BACKFILL));
        cumulative.addAll(PatScopes.V6_ADDED);
        assertThat(PatScopes.clean(cumulative)).isEqualTo(PatScopes.ALL);
        assertThat(PatScopes.V6_ADDED).containsExactly("board:read", "board:write", "search:read");
        assertThat(PatScopes.join(PatScopes.ALL).length()).isLessThanOrEqualTo(255); // 컬럼 폭
    }

    private String migration(String name) throws IOException {
        try (InputStream in = getClass().getClassLoader().getResourceAsStream("db/migration/" + name)) {
            assertThat(in).as(name).isNotNull();
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}
