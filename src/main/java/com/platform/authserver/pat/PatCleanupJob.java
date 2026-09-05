package com.platform.authserver.pat;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

/**
 * 만료·폐기된 PAT의 물리 삭제 배치. RT 청소({@code TokenCleanupJob})와 같은 cron으로 돈다.
 *
 * <p>폐기 직후 지우지 않고 보존 기간을 두는 이유는 감사다 — "언제 누가 무엇을 폐기했는가"가
 * 유출 대응의 기록이다. RT와 달리 재사용 탐지 증거물은 아니므로 가족 개념 없이 행 단위로 지운다.
 */
@Component
public class PatCleanupJob {

    private static final Logger log = LoggerFactory.getLogger(PatCleanupJob.class);

    private final PersonalAccessTokenRepository tokenRepository;
    private final long retentionDays;

    public PatCleanupJob(PersonalAccessTokenRepository tokenRepository,
                         @Value("${platform.pat-retention-days}") long retentionDays) {
        this.tokenRepository = tokenRepository;
        this.retentionDays = retentionDays;
    }

    @Scheduled(cron = "${platform.token-cleanup-cron:0 0 4 * * *}")
    @Transactional
    public void cleanup() {
        Instant cutoff = Instant.now().minus(retentionDays, ChronoUnit.DAYS);
        int deleted = tokenRepository.deleteStale(cutoff);
        if (deleted > 0) {
            log.info("PAT 청소 배치: 만료·폐기 후 {}일 지난 토큰 {}건 삭제", retentionDays, deleted);
        }
    }
}
