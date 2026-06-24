package com.platform.authserver.user;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@DataJpaTest
@ActiveProfiles("test")
@Import(UserService.class)
class UserServiceTest {

    @Autowired UserService userService;
    @Autowired UserRepository userRepository;

    @Test
    void createsUserOnFirstLogin() {
        User u = userService.provision("kc-sub-1", "alice@demo.com", "Alice", List.of("USER"), "GOOGLE");

        assertThat(u.getId()).isNotNull();
        assertThat(u.getKeycloakSub()).isEqualTo("kc-sub-1");
        assertThat(u.getRoles()).containsExactly("USER");
        assertThat(userRepository.count()).isEqualTo(1);
    }

    @Test
    void reusesUserAndUpdatesProfileOnSecondLogin() {
        userService.provision("kc-sub-1", "alice@demo.com", "Alice", List.of("USER"), "GOOGLE");
        User again = userService.provision("kc-sub-1", "alice@new.com", "Alice K", List.of("USER", "ADMIN"), "GOOGLE");

        assertThat(userRepository.count()).isEqualTo(1);
        assertThat(again.getEmail()).isEqualTo("alice@new.com");
        assertThat(again.getRoles()).containsExactly("USER", "ADMIN");
        assertThat(again.getLastLoginAt()).isNotNull();
    }
}
