package com.platform.authserver.agent;

import com.platform.authserver.jwt.JwtService;
import com.platform.authserver.user.User;
import com.platform.authserver.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

/**
 * 에이전트 페르소나 사용자(로그인 불가, keycloak_sub="agent:"+slug) 생성/조회와
 * 그 사용자로의 서비스 토큰 발급. 로그인 JIT 경로({@code UserService.provision})와는
 * 완전히 별개 — 절대 그쪽 로직을 공유하거나 침범하지 않는다.
 */
@Service
@RequiredArgsConstructor
public class AgentUserService {

    private static final String AGENT_PREFIX = "agent:";

    private final UserRepository userRepository;
    private final JwtService jwtService;

    public record AgentResult(long userId, String slug, boolean created) {}

    /** slug로 에이전트 페르소나 사용자를 멱등 생성/조회. 이미 있으면 name/email만 갱신한다. */
    @Transactional
    public AgentResult createOrGet(String slug, String name, String email) {
        String keycloakSub = AGENT_PREFIX + slug;
        Optional<User> existing = userRepository.findByKeycloakSub(keycloakSub);
        boolean created = existing.isEmpty();
        User user = existing.orElseGet(() -> new User(keycloakSub));
        user.setName(name);
        user.setEmail(email);
        if (created) {
            user.setRoles(List.of("USER"));
            user.setProvider("AGENT");
        }
        User saved = userRepository.save(user);
        return new AgentResult(saved.getId(), slug, created);
    }

    /**
     * userId로 900s AT 발급. keycloak_sub가 "agent:"로 시작하는 페르소나가 아니면 빈
     * Optional — 사람 계정은 이 경로로 절대 토큰을 받을 수 없다(호출부가 403으로 매핑).
     */
    public Optional<String> mint(long userId) {
        return userRepository.findById(userId)
                .filter(u -> u.getKeycloakSub() != null && u.getKeycloakSub().startsWith(AGENT_PREFIX))
                .map(u -> jwtService.issueAccessToken(u.getId(), u.getEmail(), u.getName(), u.getRoles(), "AGENT"));
    }
}
