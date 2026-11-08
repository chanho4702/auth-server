package com.platform.authserver.invite;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 아웃바운드 auth → org 호출이 싣는 {@code X-Internal-Token}(N5 — {@code ORG_IDENTITY_TOKEN}, 비면 {@code ORG_INTERNAL_TOKEN}).
 * 프로퍼티 해석(폴백)은 {@code InternalSecretSplitTest}가, 여기서는 그 값이 헤더에 어떻게 실리는지를 본다.
 */
class OrgInternalClientTokenTest {

    HttpServer server;
    final List<String> seenTokens = new CopyOnWriteArrayList<>();

    @BeforeEach
    void start() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            seenTokens.add(exchange.getRequestHeaders().getFirst("X-Internal-Token"));
            byte[] body = "{\"email\":\"a@test.com\",\"status\":\"PENDING\",\"globalAdmin\":true}"
                    .getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.start();
    }

    @AfterEach
    void stop() {
        server.stop(0);
    }

    String baseUri() {
        return "http://127.0.0.1:" + server.getAddress().getPort();
    }

    @Test
    void 설정한_신원_토큰을_헤더에_싣는다() {
        OrgInternalClient client = new OrgInternalClient(baseUri(), "identity-token");
        assertThat(client.findInvite("tok")).isPresent();
        assertThat(client.globalAdmin(1L)).isEqualTo(OrgInternalClient.AdminCheck.ADMIN);
        assertThat(seenTokens).containsExactly("identity-token", "identity-token");
    }

    /** 회전 중 폴백 값이 "신,구" 목록이어도(수신용으로 넣은 ORG_INTERNAL_TOKEN) 보내는 쪽은 첫 항목 하나만 싣는다. */
    @Test
    void 콤마_목록이면_첫_비어있지_않은_항목_하나만_보낸다() {
        OrgInternalClient client = new OrgInternalClient(baseUri(), " , new-token , old-token");
        client.ensureMember(1L, "a@test.com", "A", "keycloak");
        assertThat(seenTokens).containsExactly("new-token");
    }

    @Test
    void 비어있으면_미설정이고_호출하지_않는다() {
        OrgInternalClient client = new OrgInternalClient(baseUri(), " , ");
        assertThat(client.isConfigured()).isFalse();
        assertThat(client.findInvite("tok")).isEmpty();
        assertThat(seenTokens).isEmpty();
    }
}
