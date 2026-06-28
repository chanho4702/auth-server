-- 백채널(서버-서버) 로그아웃용 Keycloak refresh_token 보관 컬럼.
-- 기존 id_token(hint) 방식은 토큰 만료로 KC SSO 세션을 못 끊어 "재로그인 즉시" 문제가 있었다.
-- refresh_token 은 SSO 세션과 함께 살아있어, 로그아웃 시점에 KC end_session 을 서버-서버로 호출해
-- SSO 세션을 확실히 종료할 수 있다.
ALTER TABLE refresh_tokens ADD COLUMN kc_refresh_token TEXT;
