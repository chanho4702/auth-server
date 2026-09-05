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
}
