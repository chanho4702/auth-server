package com.platform.authserver.pat;

import com.platform.authserver.TestOAuth2ClientConfig;
import com.platform.authserver.token.RefreshTokenService;
import com.platform.authserver.user.User;
import com.platform.authserver.user.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * F-21 — PAT 이름 변경({@code PATCH /api/auth/tokens/{id}})과 내 토큰 전부 폐기({@code DELETE /api/auth/tokens}).
 * 이름 규칙은 발급과 같고(trim 후 1~100자, 위반은 {@code label_required}), 남의 토큰은 404.
 */
@SpringBootTest
@ActiveProfiles("test")
@Import(TestOAuth2ClientConfig.class)
class PersonalAccessTokenRenameRevokeAllTest {

    @Autowired WebApplicationContext context;
    @Autowired PersonalAccessTokenRepository tokenRepository;
    @Autowired UserRepository userRepository;

    MockMvc mvc;
    User alice;
    User bob;

    @BeforeEach
    void setup() {
        mvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
        tokenRepository.deleteAll();
        userRepository.deleteAll();
        alice = newUser("kc-alice");
        bob = newUser("kc-bob");
    }

    private User newUser(String sub) {
        User u = new User(sub + "-" + System.nanoTime());
        u.setRoles(List.of("USER"));
        u.setProvider("KEYCLOAK");
        return userRepository.save(u);
    }

    private RequestPostProcessor as(User user) {
        return jwt().jwt(j -> j.subject(String.valueOf(user.getId())).claim("provider", "KEYCLOAK")
                .claim("roles", List.of("USER")));
    }

    private RequestPostProcessor asPatJwt(User user) {
        return jwt().jwt(j -> j.subject(String.valueOf(user.getId())).claim("provider", "PAT")
                .claim("roles", List.of("USER")));
    }

    private PersonalAccessToken persist(User owner, String label) {
        String raw = PersonalAccessTokenService.TOKEN_PREFIX + UUID.randomUUID();
        Instant now = Instant.now();
        return tokenRepository.save(new PersonalAccessToken(owner.getId(), label,
                RefreshTokenService.sha256(raw), raw.substring(raw.length() - 4),
                List.of(PatScopes.WIKI_READ), now, now.plus(30, ChronoUnit.DAYS)));
    }

    // ---------- 이름 변경 ----------

    @Test
    void rename_returns_the_list_item_shape_with_the_new_label() throws Exception {
        PersonalAccessToken t = persist(alice, "옛 이름");

        mvc.perform(patch("/api/auth/tokens/" + t.getId()).with(as(alice))
                        .contentType(MediaType.APPLICATION_JSON).content("{\"name\":\"  새 이름  \"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(t.getId().toString()))
                .andExpect(jsonPath("$.label").value("새 이름"))
                .andExpect(jsonPath("$.hint").value(t.getTokenHint()))
                .andExpect(jsonPath("$.scopes[0]").value("wiki:read"))
                .andExpect(jsonPath("$.token").doesNotExist());

        assertThat(tokenRepository.findById(t.getId()).orElseThrow().getLabel()).isEqualTo("새 이름");
    }

    @Test
    void rename_also_accepts_label_like_create() throws Exception {
        PersonalAccessToken t = persist(alice, "옛 이름");
        mvc.perform(patch("/api/auth/tokens/" + t.getId()).with(as(alice))
                        .contentType(MediaType.APPLICATION_JSON).content("{\"label\":\"CI\"}"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.label").value("CI"));
    }

    @Test
    void rename_validates_like_create() throws Exception {
        PersonalAccessToken t = persist(alice, "옛 이름");
        for (String body : List.of("{}", "{\"name\":\"   \"}", "{\"name\":\"" + "가".repeat(101) + "\"}")) {
            mvc.perform(patch("/api/auth/tokens/" + t.getId()).with(as(alice))
                            .contentType(MediaType.APPLICATION_JSON).content(body))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.error").value("label_required"));
        }
        assertThat(tokenRepository.findById(t.getId()).orElseThrow().getLabel()).isEqualTo("옛 이름");
    }

    @Test
    void rename_of_someone_elses_or_unknown_token_is_404() throws Exception {
        PersonalAccessToken bobs = persist(bob, "밥의 토큰");
        mvc.perform(patch("/api/auth/tokens/" + bobs.getId()).with(as(alice))
                        .contentType(MediaType.APPLICATION_JSON).content("{\"name\":\"가로채기\"}"))
                .andExpect(status().isNotFound()).andExpect(jsonPath("$.error").value("not_found"));
        mvc.perform(patch("/api/auth/tokens/" + UUID.randomUUID()).with(as(alice))
                        .contentType(MediaType.APPLICATION_JSON).content("{\"name\":\"x\"}"))
                .andExpect(status().isNotFound());
        mvc.perform(patch("/api/auth/tokens/not-a-uuid").with(as(alice))
                        .contentType(MediaType.APPLICATION_JSON).content("{\"name\":\"x\"}"))
                .andExpect(status().isNotFound());
        assertThat(tokenRepository.findById(bobs.getId()).orElseThrow().getLabel()).isEqualTo("밥의 토큰");
    }

    // ---------- 전부 폐기 ----------

    @Test
    void revoke_all_revokes_only_my_active_tokens_and_keeps_rows() throws Exception {
        PersonalAccessToken a1 = persist(alice, "a1");
        PersonalAccessToken a2 = persist(alice, "a2");
        PersonalAccessToken b1 = persist(bob, "b1");

        mvc.perform(delete("/api/auth/tokens").with(as(alice))).andExpect(status().isNoContent());

        assertThat(tokenRepository.findById(a1.getId()).orElseThrow().isRevoked()).isTrue();
        assertThat(tokenRepository.findById(a2.getId()).orElseThrow().isRevoked()).isTrue();
        assertThat(tokenRepository.findById(b1.getId()).orElseThrow().isRevoked()).isFalse();
    }

    @Test
    void revoke_all_is_idempotent_and_keeps_earlier_revocation_time() throws Exception {
        PersonalAccessToken a1 = persist(alice, "a1");
        mvc.perform(delete("/api/auth/tokens/" + a1.getId()).with(as(alice))).andExpect(status().isNoContent());
        Instant first = tokenRepository.findById(a1.getId()).orElseThrow().getRevokedAt();

        mvc.perform(delete("/api/auth/tokens").with(as(alice))).andExpect(status().isNoContent());
        mvc.perform(delete("/api/auth/tokens").with(as(alice))).andExpect(status().isNoContent());

        assertThat(tokenRepository.findById(a1.getId()).orElseThrow().getRevokedAt()).isEqualTo(first);
    }

    // ---------- 인증 ----------

    @Test
    void pat_issued_jwt_cannot_rename_or_revoke_all() throws Exception {
        PersonalAccessToken t = persist(alice, "a1");
        mvc.perform(patch("/api/auth/tokens/" + t.getId()).with(asPatJwt(alice))
                        .contentType(MediaType.APPLICATION_JSON).content("{\"name\":\"x\"}"))
                .andExpect(status().isForbidden()).andExpect(jsonPath("$.error").value("pat_cannot_manage_tokens"));
        mvc.perform(delete("/api/auth/tokens").with(asPatJwt(alice)))
                .andExpect(status().isForbidden()).andExpect(jsonPath("$.error").value("pat_cannot_manage_tokens"));
        assertThat(tokenRepository.findById(t.getId()).orElseThrow().isRevoked()).isFalse();
    }

    @Test
    void anonymous_rename_and_revoke_all_are_unauthorized() throws Exception {
        PersonalAccessToken t = persist(alice, "a1");
        mvc.perform(patch("/api/auth/tokens/" + t.getId())
                        .contentType(MediaType.APPLICATION_JSON).content("{\"name\":\"x\"}"))
                .andExpect(status().isUnauthorized());
        mvc.perform(delete("/api/auth/tokens")).andExpect(status().isUnauthorized());
        assertThat(tokenRepository.findById(t.getId()).orElseThrow().isRevoked()).isFalse();
    }
}
