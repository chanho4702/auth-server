package com.platform.authserver.config;

import com.platform.authserver.TestOAuth2ClientConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Actuator 노출 범위. 헬스/버전은 도커 네트워크 안에서 게이트웨이가 로그인 없이 긁어야 하고
 * ({@code SecurityConfig.actuatorChain}), 나머지 엔드포인트는 아예 노출되지 않아야 한다.
 * webChain에 흘러들어가 Keycloak 로그인으로 302되던 회귀를 여기서 고정한다.
 */
@SpringBootTest
@ActiveProfiles("test")
@Import(TestOAuth2ClientConfig.class)
class ActuatorEndpointsTest {

    @Autowired WebApplicationContext context;

    MockMvc mvc;

    @BeforeEach
    void setup() {
        mvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
    }

    @Test
    void health_is_anonymous_200_with_component_details() throws Exception {
        mvc.perform(get("/actuator/health"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("UP"))
                // show-details: always — 게이트웨이가 components.db로 Postgres 상태를 판정한다.
                .andExpect(jsonPath("$.components.db.status").value("UP"));
    }

    @Test
    void info_is_anonymous_200() throws Exception {
        mvc.perform(get("/actuator/info")).andExpect(status().isOk());
    }

    @Test
    void other_actuator_endpoints_are_not_exposed() throws Exception {
        for (String path : new String[]{"/actuator/env", "/actuator/beans", "/actuator/metrics", "/actuator"}) {
            int statusCode = mvc.perform(get(path)).andReturn().getResponse().getStatus();
            assertThat(statusCode)
                    .as("%s 는 익명에게 열려 있으면 안 된다", path)
                    .isNotEqualTo(200);
        }
    }
}
