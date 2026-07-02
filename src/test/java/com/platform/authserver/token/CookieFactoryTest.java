package com.platform.authserver.token;

import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseCookie;

import static org.assertj.core.api.Assertions.assertThat;

class CookieFactoryTest {

    @Test
    void refreshCookieIsHttpOnlyLaxScopedToAuthPath() {
        CookieFactory factory = new CookieFactory(1209600, false);

        ResponseCookie cookie = factory.refreshCookie("raw-rt");

        assertThat(cookie.getName()).isEqualTo(CookieFactory.COOKIE_NAME);
        assertThat(cookie.getValue()).isEqualTo("raw-rt");
        assertThat(cookie.isHttpOnly()).isTrue();
        assertThat(cookie.isSecure()).isFalse();
        assertThat(cookie.getSameSite()).isEqualTo("Lax");
        assertThat(cookie.getPath()).isEqualTo("/api/auth");
        assertThat(cookie.getMaxAge().getSeconds()).isEqualTo(1209600);
    }

    @Test
    void secureFlagFollowsConfiguration() {
        CookieFactory factory = new CookieFactory(1209600, true);

        assertThat(factory.refreshCookie("raw-rt").isSecure()).isTrue();
        assertThat(factory.deleteCookie().isSecure()).isTrue();
    }

    @Test
    void deleteCookieExpiresImmediately() {
        CookieFactory factory = new CookieFactory(1209600, false);

        ResponseCookie cookie = factory.deleteCookie();

        assertThat(cookie.getValue()).isEmpty();
        assertThat(cookie.getMaxAge().getSeconds()).isZero();
        assertThat(cookie.getPath()).isEqualTo("/api/auth");
    }
}
