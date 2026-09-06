package com.platform.authserver.pat;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

/**
 * PAT 스코프의 허용 집합과 정규화 규칙. 저장(쉼표 구분 문자열)·교환 JWT의 {@code scope}
 * 클레임·발급 요청 검증이 모두 이 한 곳을 본다.
 *
 * <p>스코프의 <b>강제</b>는 여기서 하지 않는다 — 게이트웨이의 {@code PatScopeWebFilter}가
 * 경로/메서드를 보고 판단한다. auth-server는 "무엇을 허용했는지"만 정확히 담아 넘긴다.
 *
 * <p>정규화는 중복 제거 + 사전순 정렬이다. 저장 문자열이 입력 순서에 따라 달라지면
 * 목록 응답과 JWT 클레임이 요청마다 흔들려 프론트 칩 순서·캐시 비교가 불안정해진다.
 */
public final class PatScopes {

    public static final String WIKI_READ = "wiki:read";
    public static final String WIKI_WRITE = "wiki:write";
    public static final String ALM_READ = "alm:read";
    public static final String ALM_WRITE = "alm:write";
    public static final String ORG_READ = "org:read";
    public static final String ORG_WRITE = "org:write";
    /** 각 서비스의 관리 경로(제품별 admin 경로, migration, agent)에 추가로 요구되는 스코프. */
    public static final String ADMIN = "admin";

    /**
     * 허용 스코프 전체(정규화 순서 = 사전순). V5 마이그레이션의 기존 행 백필 문자열이
     * 이 목록과 같아야 한다.
     */
    public static final List<String> ALL = List.of(
            ADMIN, ALM_READ, ALM_WRITE, ORG_READ, ORG_WRITE, WIKI_READ, WIKI_WRITE);

    private static final Set<String> ALLOWED = Set.copyOf(ALL);
    private static final String DELIMITER = ",";

    private PatScopes() {}

    public static boolean isAllowed(String scope) {
        return scope != null && ALLOWED.contains(scope);
    }

    /**
     * 공백 제거 · 빈 값 제거 · 중복 제거 · 정렬만 한다. 허용 여부는 보지 않는다 —
     * "비어 있음"({@code scopes_required})과 "모르는 값"({@code scopes_invalid})을 컨트롤러가
     * 구분해 응답하려면 두 판정이 분리돼 있어야 한다.
     */
    public static List<String> clean(Collection<String> raw) {
        if (raw == null) {
            return List.of();
        }
        TreeSet<String> sorted = new TreeSet<>();
        for (String scope : raw) {
            if (scope == null) {
                continue;
            }
            String trimmed = scope.trim();
            if (!trimmed.isEmpty()) {
                sorted.add(trimmed);
            }
        }
        return List.copyOf(sorted);
    }

    /** 대소문자·별칭 관용 없음 — 정확히 {@link #ALL}에 있는 값만 통과한다. */
    public static boolean allAllowed(Collection<String> scopes) {
        return scopes != null && !scopes.isEmpty() && scopes.stream().allMatch(PatScopes::isAllowed);
    }

    /**
     * {@link #clean} + 검증. 서비스 계층의 마지막 방어선이라 컨트롤러 검증과 겹친다 —
     * 컨트롤러를 거치지 않는 호출부(테스트·향후 내부 발급)가 스코프 없는 토큰을 만들지 못하게 한다.
     *
     * @throws IllegalArgumentException 비었거나 허용 집합에 없는 값이 섞였을 때
     */
    public static List<String> normalize(Collection<String> raw) {
        List<String> cleaned = clean(raw);
        if (cleaned.isEmpty()) {
            throw new IllegalArgumentException("스코프를 하나 이상 지정해야 합니다");
        }
        if (!allAllowed(cleaned)) {
            throw new IllegalArgumentException("알 수 없는 스코프가 있습니다");
        }
        return cleaned;
    }

    /** 정규화된 목록 → 저장 문자열. */
    public static String join(Collection<String> scopes) {
        return scopes == null ? "" : String.join(DELIMITER, scopes);
    }

    /** 저장 문자열 → 목록. 값이 없으면 빈 목록(NOT NULL이라 정상 경로에서는 나오지 않는다). */
    public static List<String> parse(String stored) {
        if (stored == null || stored.isBlank()) {
            return List.of();
        }
        return Arrays.stream(stored.split(DELIMITER))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .toList();
    }
}
