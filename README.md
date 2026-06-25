# auth-server

Keycloak에 OIDC 로그인을 **위임**받아, 플랫폼 전용 **자체 RS256 JWT**를 발급하는 인증 서버.
myFront(React) 같은 클라이언트는 Keycloak 토큰이 아니라 **이 서버가 발급한 JWT**만 들고 다닌다.

> 별도 git repo: `github.com/chanho4702/auth-server` (브랜치 `main`). 우산 repo(MSA_TEMPLATE)에서는 gitignore 됨.

---

## 역할 / 아키텍처

```
[myFront :5173]
   │  ① "로그인" → 리다이렉트
   ▼
[auth-server :9000]  ──②위임──▶  [Keycloak :8080 / realm sso-demo]
   │  ③로그인 성공 시: JIT 사용자 생성 + 자체 JWT 발급 + refresh 쿠키
   │  ④ /app 으로 리다이렉트
   ▼
[PostgreSQL :5433 / authdb]  (users, refresh_tokens)
```

- **인증**은 Keycloak이 담당(계정·구글 SSO·로그인 화면).
- **토큰 발급**은 auth-server가 담당 — 자체 RS256 JWT(Access Token) + 회전형 Refresh Token.
- `/.well-known/jwks.json`로 **공개키만** 노출 → 미래 마이크로서비스가 `issuer-uri`(=`http://localhost:9000`)만으로 토큰 검증 가능(SSO 토대).

## 기술 스택

Spring Boot 4.0.6 · Java 24 · Gradle · Spring Security(oauth2-client / resource-server) · Spring Data JPA · Flyway · PostgreSQL · Nimbus JOSE+JWT(RS256) · Lombok

---

## 빠른 시작

**전제:** Keycloak + Postgres가 먼저 떠 있어야 한다 → [`../infra/README.md`](../infra/README.md) 참고 (`cd infra/keycloak && docker compose up -d`).

```powershell
# Windows PowerShell — JDK 24 필요(기본 JDK가 11이면 실패)
$env:JAVA_HOME = 'C:\Program Files\Java\jdk-24'
.\gradlew.bat bootRun        # :9000 기동
```

기동 확인: `http://localhost:9000/.well-known/jwks.json` → `{"keys":[{"kty":"RSA",...}]}`

## 엔드포인트

| 메서드 | 경로 | 인증 | 설명 |
|---|---|---|---|
| GET | `/oauth2/authorization/keycloak` | - | OIDC 로그인 시작(Keycloak로 리다이렉트). `?kc_idp_hint=google`로 구글 직행 |
| GET | `/.well-known/jwks.json` | - | 서명 공개키(JWK Set) |
| POST | `/api/auth/refresh` | RT 쿠키 | RT 회전 + 새 Access Token `{accessToken}` 발급 |
| POST | `/api/auth/logout` | RT 쿠키 | 토큰 패밀리 폐기 + `{keycloakLogoutUrl}`(Keycloak end_session) 반환 + 쿠키 삭제 |
| GET | `/api/me` | Bearer(자체 JWT) | 토큰 claim 기반 사용자 정보 `{sub,email,name,role,provider}` |

## 토큰 모델

- **Access Token**: RS256 JWT, 15분, claim `iss/sub(=users.id)/email/name/roles/provider/iat/exp`. 메모리 보관(프론트).
- **Refresh Token**: opaque 32바이트 랜덤, 14일. 쿠키 `refresh_token`(HttpOnly·SameSite=Lax·Secure=false(dev)·Path=/api/auth). **DB에는 SHA-256 해시만 저장**(원문 저장 안 함).
- **회전 + 재사용 탐지**: refresh마다 새 토큰으로 교체하고 옛 토큰 폐기. 이미 교체된(폐기된) 토큰이 다시 쓰이면 **도난으로 간주해 토큰 패밀리 전체를 폐기**한다.

## 서명 키 — `auth-jwk.json`

첫 기동 시 RSA 키쌍을 생성해 `./auth-jwk.json`에 저장하고, 이후엔 이 파일을 로드(재시작해도 발급 토큰 유효하도록 키 고정). **개인키 포함 → 커밋 금지**(`.gitignore`에 등록됨). 운영에선 파일 대신 시크릿 매니저로 주입 권장. 경로는 `platform.jwk-path`로 변경 가능.

## 설정 (`src/main/resources/application.yml`)

| 키 | 기본값 |
|---|---|
| `server.port` | 9000 |
| `spring.datasource.url` | `jdbc:postgresql://localhost:5433/authdb` (user/pw `keycloak`) |
| `spring.security.oauth2.client...keycloak.issuer-uri` | `http://localhost:8080/realms/sso-demo` |
| `platform.access-token-ttl-seconds` | 900 |
| `platform.refresh-token-ttl-seconds` | 1209600 (14d) |
| `platform.frontend-url` | `http://localhost:5173` |
| `platform.cors-allowed-origin` | `http://localhost:5173` |

## 테스트 / 빌드

```powershell
$env:JAVA_HOME = 'C:\Program Files\Java\jdk-24'
.\gradlew.bat test     # JUnit 전체 (현재 14개)
```

- 테스트는 H2 인메모리 + Hibernate 자동 DDL을 쓰고 Flyway/실제 Keycloak에 의존하지 않는다.
- `@SpringBootTest`는 `TestOAuth2ClientConfig`(오프라인 `ClientRegistrationRepository`)를 import해 Keycloak 없이 컨텍스트가 뜬다.

## 디렉토리

```
src/main/java/com/platform/authserver/
├─ AuthServerApplication.java
├─ jwt/       JwtKeyProvider · JwtService · JwksController   (RS256 발급 + JWKS)
├─ user/      User · UserRepository · UserService            (JIT 프로비저닝)
├─ token/     RefreshToken(+Repository) · RefreshTokenService · CookieFactory · ReuseDetectedException
├─ auth/      OidcClaims · LoginSuccessHandler · AuthController · MeController
└─ config/    SecurityConfig                                 (2개 필터체인 + CORS + JwtDecoder)
src/main/resources/db/migration/V1__init.sql                 (Flyway: users, refresh_tokens)
```

보안 필터체인 2개: `/api/me` = 자체 JWT 리소스서버(stateless), 그 외 = oauth2Login + `/api/auth/**`·`/.well-known/**`·`/error` permitAll.

## 트러블슈팅

- **`Gradle requires JVM 17 or later`** → `JAVA_HOME`을 JDK 24로. (기본이 11)
- **부팅 시 `Schema validation: missing table refresh_tokens`** → Flyway가 안 돈 것. `spring-boot-flyway` 의존성이 있는지 확인(Boot 4는 autoconfig가 모듈 분리됨). authdb가 비어있으면 infra를 `docker compose down -v && up -d`로 재초기화.
- **부팅 시 `Connection refused .../openid-configuration`** → Keycloak(:8080)이 안 떠 있음. infra 먼저 기동.
- **로그인 후 `/api/me`가 401** → Access Token(Bearer) 없이 호출했거나 만료. `/api/auth/refresh`로 새 토큰부터.
