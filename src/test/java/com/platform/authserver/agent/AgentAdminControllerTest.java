package com.platform.authserver.agent;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.platform.authserver.TestOAuth2ClientConfig;
import com.platform.authserver.user.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@ActiveProfiles("test")
@Import(TestOAuth2ClientConfig.class)
class AgentAdminControllerTest {

    @Autowired WebApplicationContext context;
    @Autowired UserRepository userRepository;
    MockMvc mvc;
    final ObjectMapper objectMapper = new ObjectMapper();

    @BeforeEach
    void setup() {
        mvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
        userRepository.deleteAll();
    }

    @Test
    void admin_creates_agent_user_idempotently() throws Exception {
        String body = "{\"slug\":\"jiho\",\"name\":\"지호\"}";

        String firstResponse = mvc.perform(post("/api/auth/agents")
                        .with(jwt().jwt(j -> j.subject("1").claim("roles", List.of("ADMIN")))
                                .authorities(new SimpleGrantedAuthority("ROLE_ADMIN")))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        Map<?, ?> first = objectMapper.readValue(firstResponse, Map.class);
        assertThat(((Number) first.get("userId")).longValue()).isGreaterThan(0);
        assertThat(first.get("slug")).isEqualTo("jiho");
        assertThat(first.get("created")).isEqualTo(true);
        assertThat(userRepository.count()).isEqualTo(1);

        String secondResponse = mvc.perform(post("/api/auth/agents")
                        .with(jwt().jwt(j -> j.subject("1").claim("roles", List.of("ADMIN")))
                                .authorities(new SimpleGrantedAuthority("ROLE_ADMIN")))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        Map<?, ?> second = objectMapper.readValue(secondResponse, Map.class);
        assertThat(second.get("userId")).isEqualTo(first.get("userId"));
        assertThat(second.get("created")).isEqualTo(false);
        assertThat(userRepository.count()).isEqualTo(1);
    }

    @Test
    void non_admin_forbidden() throws Exception {
        mvc.perform(post("/api/auth/agents")
                        .with(jwt().jwt(j -> j.subject("1").claim("roles", List.of("USER")))
                                .authorities(new SimpleGrantedAuthority("ROLE_USER")))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"slug\":\"jiho\",\"name\":\"지호\"}"))
                .andExpect(status().isForbidden());
    }

    @Test
    void bad_slug_rejected() throws Exception {
        mvc.perform(post("/api/auth/agents")
                        .with(jwt().jwt(j -> j.subject("1").claim("roles", List.of("ADMIN")))
                                .authorities(new SimpleGrantedAuthority("ROLE_ADMIN")))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"slug\":\"Jiho!\",\"name\":\"지호\"}"))
                .andExpect(status().isBadRequest());
    }
}
