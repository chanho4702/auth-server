package com.platform.authserver.auth;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Keycloak 계정 재확인 클라이언트 — 가짜 Admin REST 서버로 검증한다.
 *
 * <p>핵심은 "계정 문제"(잠김·삭제)와 "가용성 문제"(KC 장애·이상 응답)를 섞지 않는 것이다 — 앞의 것은 RT 전부 폐기로,
 * 뒤의 것은 stale 판정으로 간다. 섞이면 KC가 잠깐 죽을 때 전원의 세션이 지워진다.
 */
class KeycloakAccountClientTest {

    HttpServer server;
    List<String> paths;
    volatile int tokenStatus = 200;
    volatile int userStatus = 200;
    volatile String userBody = "{\"id\":\"kc-1\",\"enabled\":true}";
    volatile int rolesStatus = 200;
    volatile String rolesBody = "[{\"name\":\"USER\"},{\"name\":\"ADMIN\"}]";

    @BeforeEach
    void start() throws IOException {
        paths = new CopyOnWriteArrayList<>();
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/realms/test/protocol/openid-connect/token", ex -> {
            paths.add("token");
            respond(ex, tokenStatus, "{\"access_token\":\"admin-at\",\"expires_in\":300}");
        });
        server.createContext("/admin/realms/test/users/", ex -> {
            String path = ex.getRequestURI().getPath();
            paths.add(path);
            if (!"Bearer admin-at".equals(ex.getRequestHeaders().getFirst("Authorization"))) {
                respond(ex, 401, "");
            } else if (path.endsWith("/role-mappings/realm/composite")) {
                respond(ex, rolesStatus, rolesBody);
            } else {
                respond(ex, userStatus, userBody);
            }
        });
        server.start();
    }

    @AfterEach
    void stop() {
        server.stop(0);
    }

    private KeycloakAccountClient client(Duration cache, Clock clock) {
        return new KeycloakAccountClient("http://127.0.0.1:" + server.getAddress().getPort() + "/realms/test",
                "platform-admin", "secret", true, cache, clock);
    }

    private KeycloakAccountClient client() {
        return client(Duration.ZERO, Clock.systemUTC());
    }

    @Test
    void 활성_계정이면_유효_realm_롤을_준다() {
        KeycloakAccountClient.Verdict v = client().check("kc-1");
        assertThat(v.kind()).isEqualTo(KeycloakAccountClient.Verdict.Kind.ACTIVE);
        assertThat(v.roles()).containsExactly("USER", "ADMIN");
        assertThat(paths).contains("/admin/realms/test/users/kc-1", "/admin/realms/test/users/kc-1/role-mappings/realm/composite");
    }

    @Test
    void 잠긴_계정은_DISABLED_삭제된_계정은_GONE() {
        userBody = "{\"id\":\"kc-1\",\"enabled\":false}";
        assertThat(client().check("kc-1").kind()).isEqualTo(KeycloakAccountClient.Verdict.Kind.DISABLED);

        userStatus = 404;
        assertThat(client().check("kc-1").kind()).isEqualTo(KeycloakAccountClient.Verdict.Kind.GONE);
    }

    @Test
    void KC_장애나_이상_응답은_계정_문제가_아니라_UNAVAILABLE이다() {
        userStatus = 500;
        assertThat(client().check("kc-1").kind()).isEqualTo(KeycloakAccountClient.Verdict.Kind.UNAVAILABLE);

        userStatus = 200;
        rolesStatus = 503;
        assertThat(client().check("kc-1").kind()).isEqualTo(KeycloakAccountClient.Verdict.Kind.UNAVAILABLE);

        tokenStatus = 401; // service account 시크릿이 틀렸다 — 계정을 닫을 근거가 아니다
        assertThat(client().check("kc-1").kind()).isEqualTo(KeycloakAccountClient.Verdict.Kind.UNAVAILABLE);

        server.stop(0); // 연결 불가
        assertThat(client().check("kc-1").kind()).isEqualTo(KeycloakAccountClient.Verdict.Kind.UNAVAILABLE);
    }

    /**
     * Codex P2: 200 + 유효 JSON인데 {@code enabled}가 없거나 boolean이 아니면 "잠김"이 아니라 "판단 불가"다.
     * 예전에는 {@code asBoolean(false)}가 DISABLED로 읽어 그 사람의 리프레시 토큰을 전부 폐기했다.
     */
    @Test
    void enabled가_없거나_boolean이_아니면_DISABLED가_아니라_UNAVAILABLE이다() {
        for (String body : List.of(
                "{\"id\":\"kc-1\"}",
                "{\"id\":\"kc-1\",\"enabled\":null}",
                "{\"id\":\"kc-1\",\"enabled\":\"false\"}",
                "{\"id\":\"kc-1\",\"enabled\":0}",
                "[]")) {
            userBody = body;
            assertThat(client().check("kc-1").kind()).as(body).isEqualTo(KeycloakAccountClient.Verdict.Kind.UNAVAILABLE);
        }
        // 명시적 boolean만 판정한다
        userBody = "{\"id\":\"kc-1\",\"enabled\":false}";
        assertThat(client().check("kc-1").kind()).isEqualTo(KeycloakAccountClient.Verdict.Kind.DISABLED);
        userBody = "{\"id\":\"kc-1\",\"enabled\":true}";
        assertThat(client().check("kc-1").kind()).isEqualTo(KeycloakAccountClient.Verdict.Kind.ACTIVE);
    }

    /**
     * Codex P2: 부정 판정(잠김·삭제)은 캐시 시간이 지나도 유지한다 — 폐기된 옛 RT로 반복 리프레시해도 KC를 다시
     * 부르지 않는다. 무효화는 성공 로그인({@link KeycloakAccountClient#evict})만 한다.
     */
    @Test
    void 부정_판정은_캐시_시간이_지나도_유지하고_evict로만_풀린다() {
        MutableClock clock = new MutableClock(Instant.parse("2026-10-24T00:00:00Z"));
        KeycloakAccountClient c = client(Duration.ofSeconds(60), clock);
        userBody = "{\"id\":\"kc-1\",\"enabled\":false}";

        assertThat(c.check("kc-1").kind()).isEqualTo(KeycloakAccountClient.Verdict.Kind.DISABLED);
        clock.advance(Duration.ofDays(3));
        assertThat(c.check("kc-1").kind()).isEqualTo(KeycloakAccountClient.Verdict.Kind.DISABLED);
        assertThat(paths.stream().filter(p -> p.endsWith("/users/kc-1")).count()).isEqualTo(1);

        userStatus = 404;
        c.check("kc-2");
        clock.advance(Duration.ofDays(3));
        assertThat(c.check("kc-2").kind()).isEqualTo(KeycloakAccountClient.Verdict.Kind.GONE);
        assertThat(paths.stream().filter(p -> p.endsWith("/users/kc-2")).count()).isEqualTo(1);

        userStatus = 200;
        userBody = "{\"id\":\"kc-1\",\"enabled\":true}";
        c.evict("kc-1"); // 성공 로그인 = KC가 다시 열었음을 확인
        assertThat(c.check("kc-1").kind()).isEqualTo(KeycloakAccountClient.Verdict.Kind.ACTIVE);
    }

    @Test
    void 시크릿이_없거나_에이전트_계정이면_확인하지_않는다() {
        KeycloakAccountClient noSecret = new KeycloakAccountClient(
                "http://127.0.0.1:" + server.getAddress().getPort() + "/realms/test", "platform-admin", "",
                true, Duration.ZERO, Clock.systemUTC());
        assertThat(noSecret.check("kc-1").kind()).isEqualTo(KeycloakAccountClient.Verdict.Kind.SKIPPED);
        assertThat(client().check("agent:jiho").kind()).isEqualTo(KeycloakAccountClient.Verdict.Kind.SKIPPED);
        assertThat(paths).isEmpty();
    }

    /** 확정 결과는 캐시 시간 동안 다시 묻지 않고, 장애(UNAVAILABLE)는 캐시하지 않는다. 관리 토큰은 재사용한다. */
    @Test
    void 확정_결과만_짧게_캐시하고_관리_토큰은_재사용한다() {
        MutableClock clock = new MutableClock(Instant.parse("2026-10-24T00:00:00Z"));
        KeycloakAccountClient c = client(Duration.ofSeconds(60), clock);

        c.check("kc-1");
        c.check("kc-1");
        assertThat(paths.stream().filter(p -> p.endsWith("/users/kc-1")).count()).isEqualTo(1);

        clock.advance(Duration.ofSeconds(61));
        c.check("kc-1");
        assertThat(paths.stream().filter(p -> p.endsWith("/users/kc-1")).count()).isEqualTo(2);
        assertThat(paths.stream().filter("token"::equals).count()).isEqualTo(1);

        userStatus = 500;
        clock.advance(Duration.ofSeconds(61));
        assertThat(c.check("kc-1").kind()).isEqualTo(KeycloakAccountClient.Verdict.Kind.UNAVAILABLE);
        userStatus = 200;
        assertThat(c.check("kc-1").kind()).isEqualTo(KeycloakAccountClient.Verdict.Kind.ACTIVE); // 장애는 기억하지 않는다

        c.evict("kc-1");
        long before = paths.stream().filter(p -> p.endsWith("/users/kc-1")).count();
        c.check("kc-1");
        assertThat(paths.stream().filter(p -> p.endsWith("/users/kc-1")).count()).isEqualTo(before + 1);
    }

    private static void respond(HttpExchange ex, int status, String body) throws IOException {
        ex.getRequestBody().readAllBytes();
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().add("Content-Type", "application/json");
        ex.sendResponseHeaders(status, bytes.length == 0 ? -1 : bytes.length);
        if (bytes.length > 0) ex.getResponseBody().write(bytes);
        ex.close();
    }

    static final class MutableClock extends Clock {
        private Instant now;
        MutableClock(Instant start) { this.now = start; }
        void advance(Duration d) { now = now.plus(d); }
        @Override public ZoneOffset getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(java.time.ZoneId zone) { return this; }
        @Override public Instant instant() { return now; }
    }
}
