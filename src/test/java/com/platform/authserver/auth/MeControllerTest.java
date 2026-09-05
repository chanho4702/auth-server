package com.platform.authserver.auth;

import com.platform.authserver.TestOAuth2ClientConfig;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.util.List;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@ActiveProfiles("test")
@Import(com.platform.authserver.TestOAuth2ClientConfig.class)
class MeControllerTest {

    @Autowired WebApplicationContext context;
    MockMvc mvc;

    @org.junit.jupiter.api.BeforeEach
    void setup() {
        mvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
    }

    @Test
    void returnsUserFromJwtClaims() throws Exception {
        mvc.perform(get("/api/me").with(jwt().jwt(j -> j
                        .subject("42")
                        .claim("email", "alice@demo.com")
                        .claim("name", "Alice")
                        .claim("provider", "GOOGLE")
                        .claim("roles", List.of("USER", "ADMIN")))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.sub").value("42"))
                .andExpect(jsonPath("$.email").value("alice@demo.com"))
                .andExpect(jsonPath("$.name").value("Alice"))
                .andExpect(jsonPath("$.provider").value("GOOGLE"))
                .andExpect(jsonPath("$.role").value("USER"))
                // roles 는 확장 필드다 — 기존 role(첫 역할 하나)은 그대로 둔다
                .andExpect(jsonPath("$.roles[0]").value("USER"))
                .andExpect(jsonPath("$.roles[1]").value("ADMIN"));
    }

    @Test
    void rejectsWithoutToken() throws Exception {
        mvc.perform(get("/api/me")).andExpect(status().isUnauthorized());
    }
}
