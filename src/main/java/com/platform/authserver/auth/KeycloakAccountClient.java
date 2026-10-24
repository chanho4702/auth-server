package com.platform.authserver.auth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 리프레시 회전 때 Keycloak 계정을 다시 확인한다(권한·계정 점검 M1 일부, B3 일부).
 *
 * <p>왜: roles는 로그인 순간의 스냅샷이라 Keycloak에서 롤을 회수하거나 계정을 잠가도 자체 RT(슬라이딩, 절대 상한
 * 90일)가 살아 있는 동안 옛 롤이 실린 AT가 계속 나갔다. 회전마다 Keycloak Admin REST로 계정 상태와 유효 realm 롤을
 * 읽어 맞춘다.
 *
 * <p><b>방법 선택 — KC refresh_token 재사용이 아니라 Admin REST(service account).</b> 보관 중인 KC refresh_token으로
 * {@code grant_type=refresh_token}을 돌리면 롤도 계정 상태도 한 번에 오지만, KC SSO 세션은 유휴 30분·최대 10시간이라
 * 자체 RT(14일)보다 훨씬 먼저 죽는다 — "세션 만료"와 "계정 잠김"을 구분할 수 없어 정상 사용자가 전부 튕긴다.
 * Admin REST는 세션과 무관하게 {@code users/{id}}(존재·enabled)와 {@code role-mappings/realm/composite}(토큰의
 * realm_access.roles와 같은 유효 롤)를 준다. 자격은 org-service가 이미 쓰는 {@code platform-admin} service
 * account(view-users)를 그대로 쓴다.
 *
 * <p><b>캐시.</b> 활성(ACTIVE)은 {@code cache-seconds}(기본 60초) 기억한다 — 탭마다 15분에 한 번 회전하므로 대부분
 * 캐시에 걸리지 않지만, 여러 탭·여러 기기가 몰릴 때 KC 왕복을 줄인다. 대가는 회수 지연 최대 60초.
 * 부정 판정(잠김·삭제)은 시간으로 풀지 않고 {@link #evict}(성공 로그인 = KC가 다시 열었음을 확인)까지 유지한다 —
 * 그 사람의 RT는 첫 판정 때 전부 폐기됐으므로 새 RT는 로그인으로만 생기고, 지워 두면 폐기된 옛 RT로 반복 리프레시할 때마다
 * KC 호출과 폐기 쿼리가 다시 돈다(값싼 부하 증폭, Codex P2). 항목 수는 닫힌 계정 수로 묶인다.
 * "모름"(KC 장애·판단할 수 없는 응답)은 캐시하지 않는다.
 *
 * <p>시크릿이 없으면(로컬·테스트) {@link Verdict.Kind#SKIPPED} — 예전 동작(스냅샷 그대로)과 같다.
 */
@Component
public class KeycloakAccountClient {

    private static final Logger log = LoggerFactory.getLogger(KeycloakAccountClient.class);

    /**
     * 확인 결과. {@code roles}는 ACTIVE일 때만 의미가 있다. {@code cached}는 KC에 묻지 않고 기억한 값이라는 뜻 —
     * 부정 판정이 캐시에서 왔다면 그 판정을 처음 받았을 때 이미 세션을 닫았다.
     */
    public record Verdict(Kind kind, List<String> roles, boolean cached) {
        public Verdict(Kind kind, List<String> roles) { this(kind, roles, false); }

        public enum Kind {
            /** 계정이 있고 enabled — roles가 최신 유효 realm 롤 */
            ACTIVE,
            /** 계정이 있으나 Keycloak에서 잠김(enabled=false) */
            DISABLED,
            /** Keycloak에 계정이 없음(삭제) */
            GONE,
            /** Keycloak에 닿지 못했거나 판단할 수 없는 응답 — 가용성 문제이지 계정 문제가 아니다 */
            UNAVAILABLE,
            /** 확인하지 않음(미설정·에이전트 계정) */
            SKIPPED
        }

        static Verdict of(Kind kind) { return new Verdict(kind, List.of()); }
    }

    private record Cached(Verdict verdict, Instant at) {}
    private record AdminToken(String value, Instant expiresAt) {}

    private final HttpClient http;
    private final ObjectMapper json = new ObjectMapper();
    private final String realmBase;
    private final String adminBase;
    private final String clientId;
    private final String clientSecret;
    private final boolean enabled;
    private final Duration cacheTtl;
    private final Clock clock;
    private final Map<String, Cached> cache = new ConcurrentHashMap<>();
    private volatile AdminToken adminToken;

    @Autowired
    public KeycloakAccountClient(
            @Value("${spring.security.oauth2.client.provider.keycloak.issuer-uri:}") String issuerUri,
            @Value("${platform.keycloak-sync.admin-client-id:platform-admin}") String clientId,
            @Value("${platform.keycloak-sync.admin-client-secret:}") String clientSecret,
            @Value("${platform.keycloak-sync.enabled:true}") boolean enabled,
            @Value("${platform.keycloak-sync.cache-seconds:60}") long cacheSeconds) {
        this(issuerUri, clientId, clientSecret, enabled, Duration.ofSeconds(Math.max(0, cacheSeconds)),
                Clock.systemUTC());
    }

    KeycloakAccountClient(String issuerUri, String clientId, String clientSecret, boolean enabled,
                          Duration cacheTtl, Clock clock) {
        this.realmBase = trimTrailingSlash(issuerUri);
        this.adminBase = toAdminBase(this.realmBase);
        this.clientId = clientId == null ? "" : clientId.trim();
        this.clientSecret = clientSecret == null ? "" : clientSecret.trim();
        this.enabled = enabled;
        this.cacheTtl = cacheTtl;
        this.clock = clock;
        // KC가 멈추면 리프레시 스레드가 함께 잠긴다 — 짧게 끊고 UNAVAILABLE로 판단을 넘긴다.
        this.http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build();
        if (enabled && !isConfigured()) {
            log.warn("Keycloak 계정 재확인 비활성 — KC_ADMIN_CLIENT_SECRET 미설정. 리프레시는 로그인 때의 roles를 그대로 쓴다.");
        }
    }

    public boolean isConfigured() {
        return enabled && !realmBase.isEmpty() && !clientId.isEmpty() && !clientSecret.isEmpty();
    }

    /**
     * @param keycloakSub users.keycloak_sub(= Keycloak user id). {@code agent:} 접두사(에이전트 페르소나)는 Keycloak 계정이
     *                    없으므로 확인하지 않는다.
     */
    public Verdict check(String keycloakSub) {
        if (!isConfigured() || keycloakSub == null || keycloakSub.isBlank() || keycloakSub.startsWith("agent:")) {
            return Verdict.of(Verdict.Kind.SKIPPED);
        }
        Cached hit = cache.get(keycloakSub);
        Instant now = clock.instant();
        if (hit != null && (isNegative(hit.verdict()) || hit.at().plus(cacheTtl).isAfter(now))) {
            Verdict v = hit.verdict();
            return new Verdict(v.kind(), v.roles(), true);
        }

        Verdict fresh = fetch(keycloakSub);
        if (fresh.kind() != Verdict.Kind.UNAVAILABLE) cache.put(keycloakSub, new Cached(fresh, now));
        return fresh;
    }

    private static boolean isNegative(Verdict v) {
        return v.kind() == Verdict.Kind.DISABLED || v.kind() == Verdict.Kind.GONE;
    }

    /** 기억한 판정을 지운다 — 성공 로그인(KC가 그 계정을 다시 열었음을 확인)에서만 부른다. 부정 판정은 이것으로만 풀린다. */
    public void evict(String keycloakSub) {
        if (keycloakSub != null) cache.remove(keycloakSub);
    }

    private Verdict fetch(String sub) {
        try {
            String token = adminToken();
            if (token == null) return Verdict.of(Verdict.Kind.UNAVAILABLE);
            HttpResponse<String> user = get(adminBase + "/users/" + enc(sub), token);
            if (user.statusCode() == 404) return Verdict.of(Verdict.Kind.GONE);
            if (user.statusCode() == 401) adminToken = null; // 토큰이 먼저 죽었다 — 다음 호출이 새로 받는다
            if (user.statusCode() / 100 != 2) {
                log.warn("Keycloak 사용자 조회 실패: status={}", user.statusCode());
                return Verdict.of(Verdict.Kind.UNAVAILABLE);
            }
            JsonNode node = json.readTree(user.body());
            // 명시적 boolean일 때만 판정한다 — 필드가 없거나 타입이 다르면 "잠김"이 아니라 "판단 불가"다.
            // asBoolean(false)로 읽으면 그 사람의 세션이 전부 폐기된다(Codex P2).
            JsonNode enabledNode = node.isObject() ? node.get("enabled") : null;
            if (enabledNode == null || !enabledNode.isBoolean()) {
                log.warn("Keycloak 사용자 응답에 boolean enabled가 없음 — 판단 불가로 처리");
                return Verdict.of(Verdict.Kind.UNAVAILABLE);
            }
            if (!enabledNode.booleanValue()) return Verdict.of(Verdict.Kind.DISABLED);

            HttpResponse<String> roles = get(adminBase + "/users/" + enc(sub) + "/role-mappings/realm/composite", token);
            if (roles.statusCode() / 100 != 2) {
                log.warn("Keycloak 롤 조회 실패: status={}", roles.statusCode());
                return Verdict.of(Verdict.Kind.UNAVAILABLE);
            }
            List<String> names = new ArrayList<>();
            for (JsonNode role : json.readTree(roles.body())) {
                String name = role.path("name").asText("");
                if (!name.isEmpty()) names.add(name);
            }
            return new Verdict(Verdict.Kind.ACTIVE, List.copyOf(names));
        } catch (Exception e) {
            // 메시지에 토큰이 섞이지 않도록 예외 종류만 남긴다.
            log.warn("Keycloak 계정 재확인 실패: {}", e.getClass().getSimpleName());
            return Verdict.of(Verdict.Kind.UNAVAILABLE);
        }
    }

    /** client_credentials 토큰 — 만료 30초 전까지 재사용한다(회전마다 토큰을 새로 받지 않게). */
    private String adminToken() throws Exception {
        AdminToken current = adminToken;
        Instant now = clock.instant();
        if (current != null && current.expiresAt().isAfter(now)) return current.value();
        String form = "grant_type=client_credentials&client_id=" + enc(clientId) + "&client_secret=" + enc(clientSecret);
        HttpResponse<String> res = http.send(HttpRequest.newBuilder()
                        .uri(URI.create(realmBase + "/protocol/openid-connect/token"))
                        .timeout(Duration.ofSeconds(3))
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .POST(HttpRequest.BodyPublishers.ofString(form, StandardCharsets.UTF_8))
                        .build(),
                HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        if (res.statusCode() / 100 != 2) {
            log.warn("Keycloak 관리 토큰 발급 실패: status={}", res.statusCode());
            return null;
        }
        JsonNode node = json.readTree(res.body());
        String value = node.path("access_token").asText("");
        if (value.isEmpty()) return null;
        long expiresIn = node.path("expires_in").asLong(60);
        adminToken = new AdminToken(value, now.plusSeconds(Math.max(0, expiresIn - 30)));
        return value;
    }

    private HttpResponse<String> get(String url, String token) throws Exception {
        return http.send(HttpRequest.newBuilder()
                        .uri(URI.create(url))
                        .timeout(Duration.ofSeconds(3))
                        .header("Authorization", "Bearer " + token)
                        .GET()
                        .build(),
                HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
    }

    private static String enc(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private static String trimTrailingSlash(String value) {
        String v = value == null ? "" : value.trim();
        while (v.endsWith("/")) v = v.substring(0, v.length() - 1);
        return v;
    }

    /** {@code http://host/realms/sso-demo} → {@code http://host/admin/realms/sso-demo} */
    private static String toAdminBase(String realmBase) {
        int at = realmBase.lastIndexOf("/realms/");
        if (at < 0) return realmBase;
        return realmBase.substring(0, at) + "/admin" + realmBase.substring(at);
    }
}
