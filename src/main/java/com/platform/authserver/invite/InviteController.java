package com.platform.authserver.invite;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;
import java.util.Optional;

/**
 * 초대 링크의 착지 지점.
 *
 * <p>하는 일은 둘이다. 토큰이 살아 있는지 org에 물어보고, 살아 있으면 세션에 담아 두고 Keycloak 로그인으로
 * 보낸다. 세션에 담는 이유는 로그인이 끝난 <b>뒤에야</b> 그 사람의 id가 생기기 때문이다 —
 * 그때 {@link com.platform.authserver.auth.LoginSuccessHandler}가 org에 수락을 알린다.
 *
 * <p>이메일은 {@code login_hint}로 넘겨 Keycloak 로그인 화면에 미리 채운다. 초대받은 주소와 다른 주소로
 * 로그인하면 org가 수락을 거절하므로, 힌트는 실수를 줄이는 편의이자 사실상의 안내다.
 *
 * <p>무효·만료 링크는 오류가 아니라 <b>안내</b>다. 사용자는 자기가 무엇을 잘못했는지 모르고, 여기서
 * 스택트레이스나 401을 보여 줄 이유가 없다.
 */
@RestController
public class InviteController {

    /** 로그인 성공 핸들러가 읽어 가는 세션 키. 일회용이다. */
    public static final String TOKEN_ATTR = "invite_token";
    public static final String EMAIL_ATTR = "invite_email";

    private final OrgInternalClient org;

    public InviteController(OrgInternalClient org) {
        this.org = org;
    }

    @GetMapping("/invite/{token}")
    public ResponseEntity<String> land(@PathVariable String token, HttpServletRequest request) {
        Optional<OrgInternalClient.InviteView> invite = org.findInvite(token);
        if (invite.isEmpty()) {
            return ResponseEntity.ok()
                    .contentType(MediaType.valueOf("text/html;charset=UTF-8"))
                    .body(invalidPage());
        }
        HttpSession session = request.getSession(true);
        session.setAttribute(TOKEN_ATTR, token);
        session.setAttribute(EMAIL_ATTR, invite.get().email());
        // Keycloak으로의 실제 리다이렉트는 Spring Security가 만든다. login_hint는
        // InviteLoginHintResolver가 이 세션 값을 보고 붙인다.
        return ResponseEntity.status(302).location(URI.create("/oauth2/authorization/keycloak")).build();
    }

    /** 링크가 죽었을 때 보여 줄 한 장. 외부 자원을 불러오지 않는다(로그인 전이라 아무것도 신뢰할 수 없다). */
    private static String invalidPage() {
        return """
                <!doctype html>
                <html lang="ko">
                <head>
                  <meta charset="utf-8">
                  <meta name="viewport" content="width=device-width, initial-scale=1">
                  <title>초대 링크를 사용할 수 없습니다</title>
                  <style>
                    body { margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center;
                           background:#f5f6f8; color:#1f2328;
                           font-family:system-ui,-apple-system,"Segoe UI",sans-serif; }
                    main { max-width:32rem; padding:2.5rem; background:#fff; border-radius:12px;
                           box-shadow:0 1px 3px rgba(0,0,0,.08); }
                    h1 { margin:0 0 .75rem; font-size:1.25rem; }
                    p  { margin:0 0 .5rem; line-height:1.7; color:#4a5057; }
                  </style>
                </head>
                <body>
                  <main>
                    <h1>초대 링크를 사용할 수 없습니다</h1>
                    <p>링크가 만료됐거나 이미 사용됐거나 철회됐습니다.</p>
                    <p>초대를 보낸 담당자에게 다시 요청해 주세요. 새 링크를 받으면 이전 링크는 더 이상 쓸 수 없습니다.</p>
                  </main>
                </body>
                </html>
                """;
    }
}
