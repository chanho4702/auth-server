package com.platform.authserver.user;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;

@Service
public class UserService {

    private final UserRepository repository;

    public UserService(UserRepository repository) {
        this.repository = repository;
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
