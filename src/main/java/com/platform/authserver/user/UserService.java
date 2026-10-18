package com.platform.authserver.user;

import com.platform.authserver.token.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserService {

    private final UserRepository repository;
    private final RefreshTokenRepository refreshTokens;

    /**
     * 계정 열기/닫기 — org-service의 구성원 상태 전파(P-02). 멱등.
     *
     * <p>닫으면 {@code enabled=false}와 함께 그 사람의 리프레시 토큰을 전부 폐기한다(모든 브라우저 세션 종료).
     * PAT는 폐기하지 않는다 — 교환이 {@code enabled}를 보고 거부하므로(같은 401), 정지 해제 시 토큰을 다시
     * 발급받지 않아도 된다. 이미 발급된 AT(최대 15분)·PAT 교환 JWT(최대 5분)는 만료까지 남는다.
     *
     * @return 사용자가 없으면 false
     */
    @Transactional
    public boolean setActive(long userId, boolean active) {
        User user = repository.findById(userId).orElse(null);
        if (user == null) return false;
        boolean changed = user.isEnabled() != active;
        user.setEnabled(active);
        int revoked = active ? 0 : refreshTokens.revokeAllForUser(userId);
        if (changed || revoked > 0) {
            log.info("계정 {}: userId={} 폐기한 리프레시 토큰={}", active ? "활성" : "비활성", userId, revoked);
        }
        return true;
    }

    /** Keycloak 로그인마다 호출. 없으면 생성, 있으면 프로필 동기화(JIT provisioning). */
    @Transactional
    public User provision(String keycloakSub, String email, String name, List<String> roles, String provider) {
        User user = repository.findByKeycloakSub(keycloakSub).orElseGet(() -> new User(keycloakSub));
        user.setEmail(email);
        user.setName(name);
        user.setRoles(roles);
        user.setProvider(provider);
        user.setLastLoginAt(Instant.now());
        return repository.save(user);
    }
}
