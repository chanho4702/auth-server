package com.platform.authserver.agent;

import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 필터 단위 테스트 — Spring 컨텍스트 없이 trim 동작만 검증한다. 게이트웨이의
 * {@code PatExchangeClient}가 자기 쪽 시크릿 사본을 trim해서 보내므로, {@code .env}에
 * 트레일링 스페이스가 섞여도(흔한 실수) auth-server 쪽 원본 시크릿과 매칭돼야 한다 —
 * trim 없이는 이 흔한 실수 하나로 모든 PAT 교환이 이유 없이 깨진다.
 */
class InternalSecretFilterTest {

    @Test
    void trims_configured_secret_before_comparing() throws Exception {
        InternalSecretFilter filter = new InternalSecretFilter("s3cret ");
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/internal/service-tokens");
        request.addHeader("X-Internal-Secret", "s3cret");
        MockHttpServletResponse response = new MockHttpServletResponse();
        AtomicBoolean reachedNext = new AtomicBoolean(false);
        FilterChain chain = (req, res) -> reachedNext.set(true);

        filter.doFilter(request, response, chain);

        assertThat(reachedNext.get()).isTrue();
    }

    @Test
    void trims_incoming_header_before_comparing() throws Exception {
        InternalSecretFilter filter = new InternalSecretFilter("s3cret");
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/internal/service-tokens");
        request.addHeader("X-Internal-Secret", " s3cret ");
        MockHttpServletResponse response = new MockHttpServletResponse();
        AtomicBoolean reachedNext = new AtomicBoolean(false);
        FilterChain chain = (req, res) -> reachedNext.set(true);

        filter.doFilter(request, response, chain);

        assertThat(reachedNext.get()).isTrue();
    }

    @Test
    void blank_after_trim_secret_is_treated_as_not_configured() throws Exception {
        InternalSecretFilter filter = new InternalSecretFilter("   ");
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/internal/service-tokens");
        request.addHeader("X-Internal-Secret", "");
        MockHttpServletResponse response = new MockHttpServletResponse();
        AtomicBoolean reachedNext = new AtomicBoolean(false);
        FilterChain chain = (req, res) -> reachedNext.set(true);

        filter.doFilter(request, response, chain);

        assertThat(reachedNext.get()).isFalse();
        assertThat(response.getStatus()).isEqualTo(403);
    }

    @Test
    void mismatched_secret_is_rejected() throws Exception {
        InternalSecretFilter filter = new InternalSecretFilter("s3cret");
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/internal/service-tokens");
        request.addHeader("X-Internal-Secret", "wrong");
        MockHttpServletResponse response = new MockHttpServletResponse();
        AtomicBoolean reachedNext = new AtomicBoolean(false);
        FilterChain chain = (req, res) -> reachedNext.set(true);

        filter.doFilter(request, response, chain);

        assertThat(reachedNext.get()).isFalse();
        assertThat(response.getStatus()).isEqualTo(403);
    }

    // ── 다중 토큰(회전, N5): "신,구" 콤마 목록 — 각 후보 상수시간 비교, trim, 빈 항목 무시 ──

    private static boolean passes(InternalSecretFilter filter, String presented) throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/internal/service-tokens");
        if (presented != null) request.addHeader("X-Internal-Secret", presented);
        MockHttpServletResponse response = new MockHttpServletResponse();
        AtomicBoolean reachedNext = new AtomicBoolean(false);
        filter.doFilter(request, response, (req, res) -> reachedNext.set(true));
        if (!reachedNext.get()) assertThat(response.getStatus()).isEqualTo(403);
        return reachedNext.get();
    }

    @Test
    void comma_list_accepts_both_new_and_old() throws Exception {
        InternalSecretFilter filter = new InternalSecretFilter("new-secret,old-secret");
        assertThat(passes(filter, "new-secret")).isTrue();
        assertThat(passes(filter, "old-secret")).isTrue();
        assertThat(passes(filter, "third-secret")).isFalse();
        // 목록 전체 문자열을 그대로 보내도 통과하지 않는다 — 항목 단위 비교다.
        assertThat(passes(filter, "new-secret,old-secret")).isFalse();
    }

    @Test
    void comma_list_trims_items_and_ignores_blanks() throws Exception {
        InternalSecretFilter filter = new InternalSecretFilter(" new-secret , ,old-secret ,");
        assertThat(passes(filter, "new-secret")).isTrue();
        assertThat(passes(filter, "old-secret")).isTrue();
        assertThat(passes(filter, "")).isFalse();
        assertThat(passes(filter, null)).isFalse();
    }

    @Test
    void comma_list_with_only_blank_items_is_fail_closed() throws Exception {
        InternalSecretFilter filter = new InternalSecretFilter(" , ,");
        assertThat(passes(filter, "")).isFalse();
        assertThat(passes(filter, ",")).isFalse();
        assertThat(passes(filter, " , ,")).isFalse();
    }

    @Test
    void null_secret_is_fail_closed() throws Exception {
        assertThat(passes(new InternalSecretFilter((String) null), "")).isFalse();
    }

    @Test
    void custom_header_variant_accepts_comma_list() throws Exception {
        InternalSecretFilter filter = new InternalSecretFilter("X-Internal-Token", "a-token,b-token", "x");
        MockHttpServletRequest request = new MockHttpServletRequest("PUT", "/internal/users/1/status");
        request.addHeader("X-Internal-Token", "b-token");
        AtomicBoolean reachedNext = new AtomicBoolean(false);
        filter.doFilter(request, new MockHttpServletResponse(), (req, res) -> reachedNext.set(true));
        assertThat(reachedNext.get()).isTrue();
    }
}
