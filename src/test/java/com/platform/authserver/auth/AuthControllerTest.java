package com.platform.authserver.auth;

import com.platform.authserver.token.RefreshTokenService;
import com.platform.authserver.user.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import jakarta.servlet.http.Cookie;
import java.util.List;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@ActiveProfiles("test")
@Import(com.platform.authserver.TestOAuth2ClientConfig.class)
class AuthControllerTest {

    @Autowired WebApplicationContext context;
    @MockitoBean RefreshTokenService refreshTokenService;
    @MockitoBean KeycloakLogoutClient keycloakLogoutClient;
    MockMvc mvc;

    @BeforeEach
    void setup() {
        mvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
    }

    @Test
    void refreshReturnsAccessTokenAndRotatesCookie() throws Exception {
        User user = new User("kc-1");
        ReflectionTestUtils.setField(user, "id", 42L);
        user.setEmail("a@b.com");
        user.setName("Alice");
        user.setRoles(List.of("USER"));
        user.setProvider("GOOGLE");
        when(refreshTokenService.rotate(eq("raw-rt")))
                .thenReturn(new RefreshTokenService.Rotated(user, "new-rt", "kc-id"));

        mvc.perform(post("/api/auth/refresh").cookie(new Cookie("refresh_token", "raw-rt")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(header().exists("Set-Cookie"));
    }

    @Test
    void refreshWithoutCookieIsUnauthorized() throws Exception {
        mvc.perform(post("/api/auth/refresh")).andExpect(status().isUnauthorized());
    }

    @Test
    void logoutTerminatesKeycloakSessionAndClearsCookie() throws Exception {
        when(refreshTokenService.revokeFamilyByRawToken(eq("raw-rt"))).thenReturn("kc-refresh-token");

        mvc.perform(post("/api/auth/logout").cookie(new Cookie("refresh_token", "raw-rt")))
                .andExpect(status().isOk())
                .andExpect(header().string("Set-Cookie", org.hamcrest.Matchers.containsString("refresh_token=;")));

        // KC SSO 세션을 백채널로 끊었는지 검증
        verify(keycloakLogoutClient).logout("kc-refresh-token");
    }
}
