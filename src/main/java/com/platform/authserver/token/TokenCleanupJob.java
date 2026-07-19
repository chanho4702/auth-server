package com.platform.authserver.token;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

/** refresh_tokens 무한 증식 방지 일 배치. 가족 단위 삭제 — 근거는 deleteDeadFamilies 주석 참고. */
@Component
public class TokenCleanupJob {

    private static final Logger log = LoggerFactory.getLogger(TokenCleanupJob.class);

    private final RefreshTokenRepository tokenRepository;

    @Value("${platform.refresh-token-ttl-seconds}")
    private long ttlSeconds;

    public TokenCleanupJob(RefreshTokenRepository tokenRepository) {
        this.tokenRepository = tokenRepository;
    }

    @Scheduled(cron = "${platform.token-cleanup-cron:0 0 4 * * *}")
    @Transactional
    public void cleanup() {
        // cutoff = now - RT TTL(버퍼): 가족 만료 후에도 탐지 유효 기간만큼 더 보존
        Instant cutoff = Instant.now().minusSeconds(ttlSeconds);
        int deleted = tokenRepository.deleteDeadFamilies(cutoff);
        if (deleted > 0) {
            log.info("RT 청소 배치: 죽은 가족 토큰 {}건 삭제", deleted);
        }
    }
}
