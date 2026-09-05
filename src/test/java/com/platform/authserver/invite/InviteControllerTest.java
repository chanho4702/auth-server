package com.platform.authserver.invite;

import com.platform.authserver.TestOAuth2ClientConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 초대 링크 착지.
 *
 * <p>계약은 셋이다. 이 경로는 <b>로그인 전에 열려 있어야</b> 한다(초대받은 사람은 아직 계정이 없다).
 * 살아 있는 토큰은 세션에 담기고 Keycloak 로그인으로 넘어가며, 그 이메일이 {@code login_hint}로 붙는다.
 * 죽은 링크는 오류가 아니라 한국어 안내다 — 사용자는 자기가 무엇을 잘못했는지 모른다.
 */
@SpringBootTest
@ActiveProfiles("test")
@Import(TestOAuth2ClientConfig.class)
class InviteControllerTest {

    @Autowired WebApplicationContext context;
    @MockitoBean OrgInternalClient orgClient;

    MockMvc mvc;

    @BeforeEach
    void setup() {
        mvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
    }

    @Test
    void 살아있는_링크는_세션에_담기고_로그인으로_보낸다() throws Exception {
        when(orgClient.findInvite(any())).thenReturn(
                Optional.of(new OrgInternalClient.InviteView("newbie@test.com", "PENDING")));

        var result = mvc.perform(get("/invite/tok-123"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/oauth2/authorization/keycloak"))
                .andReturn();

        var session = result.getRequest().getSession(false);
        assertThat(session).isNotNull();
        assertThat(session.getAttribute(InviteController.TOKEN_ATTR)).isEqualTo("tok-123");
        assertThat(session.getAttribute(InviteController.EMAIL_ATTR)).isEqualTo("newbie@test.com");
    }

    /** 초대받은 주소와 다른 계정으로 로그인하면 org가 수락을 거절한다 — 힌트는 그 실수를 미리 줄인다. */
    @Test
    void 인가_요청에_login_hint가_붙는다() throws Exception {
        when(orgClient.findInvite(any())).thenReturn(
                Optional.of(new OrgInternalClient.InviteView("newbie@test.com", "PENDING")));

        MockHttpSession session = (MockHttpSession) mvc.perform(get("/invite/tok-123"))
                .andReturn().getRequest().getSession(false);

        String authorizeUrl = mvc.perform(get("/oauth2/authorization/keycloak").session(session))
                .andExpect(status().is3xxRedirection())
                .andReturn().getResponse().getRedirectedUrl();

        assertThat(authorizeUrl).contains("login_hint=newbie@test.com");
    }

    @Test
    void 죽은_링크는_한국어_안내를_보여준다() throws Exception {
        when(orgClient.findInvite(any())).thenReturn(Optional.empty());

        mvc.perform(get("/invite/dead"))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith("text/html"))
                .andExpect(content().string(containsString("초대 링크를 사용할 수 없습니다")));
    }

    /** 로그인 전에 닫혀 있으면 초대받은 사람이 링크를 열 수조차 없다. */
    @Test
    void 초대_경로는_익명에게_열려_있다() throws Exception {
        when(orgClient.findInvite(any())).thenReturn(Optional.empty());

        mvc.perform(get("/invite/anything")).andExpect(status().isOk());
    }
}
