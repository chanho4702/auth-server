# 개인 API 토큰(PAT) 설계 — A단계: 발급·인증·관리 화면·가이드

작성 2026-09-05. 사용자 결정: 아틀라시안식 개인 API 토큰. 관리 화면은 myFront `/app`, 인증은 `Authorization: Bearer` 만, 문서는 wiki·alm·org 순(B단계). 이 문서는 A단계만 다룬다.

## 1. 목표 / 비목표

**목표**
- 로그인한 사용자가 자기 토큰을 **발급·목록·폐기**한다(라벨, 만료일, 마지막 사용 시각).
- 외부 클라이언트(스크립트·CI·타 시스템)가 `Authorization: Bearer chanho_pat_…` 로 **기존 API 전부**(`/api/wiki/**`, `/api/alm/**`, `/api/org/**`, `/api/board/**`, `/api/me`)를 호출한다. 권한은 토큰 주인의 권한과 같다.
- 리소스 서버(wiki·alm·org·board…)는 **한 줄도 바꾸지 않는다** — 게이트웨이가 PAT를 플랫폼 JWT로 바꿔 내려보내므로 서비스는 지금처럼 JWT만 본다.
- 공개 문서(`/docs/`)에 "API 인증 — 개인 토큰" 가이드 1페이지.

**비목표(후속)**
- 스코프/권한 축소 토큰, 조직 관리 토큰, Basic(이메일:토큰) 인증, 토큰별 rate-limit, OpenAPI 자동 문서(B단계).

## 2. 토큰 모델 (auth-server)

- 형식: `chanho_pat_` + base64url(SecureRandom 32바이트) = 접두사 11자 + 43자. 접두사로 게이트웨이가 PAT임을 판별한다.
- 저장: **SHA-256 해시만**(`RefreshTokenService.sha256` 재사용). 원문은 발급 응답에 **한 번만** 실린다.
- Flyway `V4__personal_access_tokens.sql`:

| 컬럼 | 타입 | 비고 |
|---|---|---|
| id | UUID PK | |
| user_id | BIGINT FK users(id) | 인덱스 |
| label | VARCHAR(100) NOT NULL | 사용자가 붙인 이름 |
| token_hash | VARCHAR(64) NOT NULL UNIQUE | hex(sha256) |
| token_hint | VARCHAR(8) NOT NULL | 원문 뒤 4자 — 목록에서 `chanho_pat_…ab12` 로 식별 |
| created_at | TIMESTAMPTZ NOT NULL | |
| expires_at | TIMESTAMPTZ NOT NULL | 발급 시 1~365일, 기본 90일 |
| last_used_at | TIMESTAMPTZ NULL | 교환 성공 시 갱신(1분에 한 번만 — 캐시 TTL과 맞춤) |
| revoked_at | TIMESTAMPTZ NULL | 폐기. 행은 남긴다(감사) |

- 사용자당 활성 토큰 최대 25개(초과 시 409 `token_limit`).
- 만료·폐기 토큰은 `TokenCleanupJob` 옆의 스케줄로 **90일 뒤** 물리 삭제.

## 3. API (auth-server)

### 3.1 관리 API — 세션 JWT 필요 (`/api/auth/tokens`)
`SecurityConfig.apiChain`의 `securityMatcher` 목록에 `/api/auth/tokens/**` 를 **반드시 추가**한다(안 하면 `webChain`의 `/api/auth/**` permitAll로 떨어진다 — 이 프로젝트의 가장 날카로운 함정). 게이트웨이는 `/api/auth/**` 를 이미 auth-server로 라우팅하고 5req/s 제한을 건다.

| Method | Path | 요청 | 응답 |
|---|---|---|---|
| GET | `/api/auth/tokens` | — | `[{id,label,hint,createdAt,expiresAt,lastUsedAt,revokedAt}]` 본인 것만, 최신순 |
| POST | `/api/auth/tokens` | `{label(1~100), expiresInDays(1~365, 기본 90)}` | 201 `{id,label,hint,createdAt,expiresAt, token}` — `token`은 이 응답에만 |
| DELETE | `/api/auth/tokens/{id}` | — | 204. 남의 토큰이면 404(존재 노출 안 함). 이미 폐기면 204(멱등) |

- **PAT로 만든 JWT(`provider=PAT`)로는 관리 API를 못 쓴다** → 403 `{"error":"pat_cannot_manage_tokens"}`. 토큰 하나가 새 토큰을 무한히 낳는 것을 막는다.
- 오류 계약은 auth 경로 관례대로 기계 코드: `{"error":"label_required"|"invalid_expiry"|"token_limit"|"not_found"}`.
- 로그: 발급·폐기는 INFO(userId, tokenId, hint). 원문·해시는 절대 로그에 남기지 않는다.

### 3.2 교환 API — 클러스터 내부 전용 (`/internal/pat/exchange`)
- `POST /internal/pat/exchange` 헤더 `X-Internal-Secret`(기존 `InternalSecretFilter`, `AGENT_INTERNAL_SECRET`), 본문 `{"token":"chanho_pat_…"}`.
- 성공 200 `{"accessToken": "<플랫폼 JWT>", "expiresInSeconds": 300}` — `JwtService.issueAccessToken(user.id, email, name, roles, provider="PAT")`. TTL은 세션 JWT(900s)보다 짧은 **300s**(`platform.pat-jwt-ttl-seconds`).
- 실패 401 `{"error":"invalid_token"}` — 없음·만료·폐기·사용자 비활성 전부 같은 응답(구분은 로그에만).
- `last_used_at`은 직전 갱신 후 60초가 지났을 때만 UPDATE.
- 게이트웨이가 `/internal/**` 을 라우팅하지 않고 nginx도 안 보내므로 외부에서 닿지 않는다(기존 구조 그대로).

## 4. 게이트웨이 교환 필터 (gateway-server)

- `PatExchangeWebFilter implements WebFilter`, `@Order(-101)` — Boot 보안 체인(`WebFilterChainProxy`, order -100)보다 **앞**. `GlobalFilter`는 보안 체인 뒤라 PAT 요청이 먼저 401로 잘려 쓸 수 없다(README 실측 순서).
- 동작: `Authorization: Bearer chanho_pat_…` 이면 →
  1. 캐시(Caffeine, 키=sha256(토큰), TTL 60s, 최대 10k) 조회. **Redis를 쓰지 않는다** — 인증 캐시가 rate-limit처럼 fail-open이면 취약점이라, 인스턴스 로컬 캐시로 둔다.
  2. 미스면 `WebClient`로 `POST {AUTH_SERVER_BASE_URI}/internal/pat/exchange`(헤더 `X-Internal-Secret`).
  3. 성공: 요청을 `exchange.mutate().request(r -> r.headers(h -> h.set("Authorization","Bearer "+jwt)))` 로 바꿔 체인 계속 → 기존 JWT 검증이 그대로 통과.
  4. 401: 즉시 401 `{"error":"invalid_token"}` 응답 + **부정 캐시 10s**(무차별 대입 완화). auth-server 불능(5xx·타임아웃 2s): 503 `{"error":"auth_unavailable"}`. 캐시된 JWT는 만료 30초 전까지만 재사용.
- PAT가 아닌 Bearer(JWT)는 건드리지 않는다. `Authorization` 없는 요청도 그대로.
- 설정: `AUTH_SERVER_BASE_URI`(docker `http://auth-server:9000`, dev `http://localhost:19000`), `AGENT_INTERNAL_SECRET`(auth-server와 같은 값, 비어 있으면 필터는 PAT를 전부 401로 — fail-closed).
- CORS: `/api/auth/tokens` 는 브라우저(myFront)에서 호출하므로 기존 CORS 설정 범위 안이다(경로 무관, 오리진 기준). 추가 변경 없음.

## 5. 운영 (infra-settings)

- 컴포즈: auth-server·gateway 양쪽에 `AGENT_INTERNAL_SECRET=${AGENT_INTERNAL_SECRET}`(현재 어디에도 없어 `/internal/service-tokens` 가 항상 403인 기존 결함도 같이 해소), gateway에 `AUTH_SERVER_BASE_URI=http://auth-server:9000`. `.env.example`에 두 키 설명, 로컬 `.env`와 `C:\deploy\platform.env`에 값 추가(`openssl rand -hex 32`).
- dev-offset(`application-dev.yml`): gateway `AUTH_SERVER_BASE_URI` 기본 `http://localhost:19000`.
- nginx·게이트웨이 라우트·허용 목록 변경 없음.

## 6. 관리 화면 (myFront `/app/tokens`)

board 패턴(`src/app/board/*`)을 그대로 따른다. `add-feature-screen` 스킬 절차 준수.
- `src/app/tokens/tokensStore.ts`: `listTokens()/createToken({label,expiresInDays})/revokeToken(id)` — `authClient.apiFetch` 경유(Bearer + 401 refresh). 오류 코드 → 한국어 메시지 매핑.
- `TokensPage.tsx`(목록): 표(라벨 · `chanho_pat_…hint` · 만든 날 · 만료 · 마지막 사용 · 상태[활성/만료/폐기]) + 상단 "새 토큰" 버튼 + 빈 상태(board 빈 상태 재사용). 만료 임박(7일) 배지.
- 발급 다이얼로그: 라벨(필수), 만료(30/90/180/365일 선택, 기본 90). 성공 시 **1회 표시 다이얼로그**: 토큰 전문 + 복사 버튼(`navigator.clipboard.writeText`, 비보안 컨텍스트 폴백은 선택 가능한 텍스트 필드) + "이 창을 닫으면 다시 볼 수 없습니다" 경고. 닫기 전 확인.
- 폐기: board 삭제 확인 다이얼로그 패턴, `useNotify` 성공/실패 토스트.
- 배선: `main.tsx` `/app` children에 `tokens`, `AppMenuContent.mainItems`에 "API 토큰"(KeyRounded 아이콘), `useCrumbs`에 `/app/tokens` 분기.
- 형제 앱 진입점(작게): wiki-front `WikiTopBar` 사용자 드롭다운에 "API 토큰" 항목, alm-front `SettingsMenu` 개인 설정 그룹에 "API 토큰" — 둘 다 `window.location.assign('/app/tokens')`(다른 SPA라 전체 이동). 읽기 전용(docs) 빌드에서는 숨김. 각 리포 게이트(typecheck·test·build) 통과.

## 7. 문서 (공개 `/docs/`)

- `auth-server/docs/api/authentication.md` — "API 인증 — 개인 API 토큰": 발급 위치(`/app/tokens`), 헤더 형식, curl 예시(`GET /api/me`, `GET /api/wiki/spaces`), 만료·폐기·한도, 오류 응답표, 보안 권고(비밀 저장소, 만료 짧게, 유출 시 폐기).
- 임포터 컬렉션 추가: `myFront/scripts/docs/collections.mjs` 에 "API 가이드" ← `auth-server/docs/api/**`. `npm run sync:docs` 로 `/docs/` 개발 문서 스페이스에 반영.

## 8. 테스트·게이트

- auth-server(`gradlew test`): 발급/목록/폐기(본인만·남의 것 404·한도 409·라벨/만료 검증), PAT-JWT로 관리 API 403, 교환(정상 → JWT 클레임 sub/provider=PAT/roles, 만료·폐기·없음 → 401, 비밀 불일치 → 403, last_used_at 1분 스로틀), `apiChain` 매처에 tokens 포함 여부(익명 GET `/api/auth/tokens` → 401 — 이게 permitAll 함정의 회귀 테스트).
- gateway-server(`gradlew test`): `WebTestClient` + MockWebServer로 필터 단독 검증 — PAT → 헤더 치환, 캐시 히트 시 auth-server 미호출, 401 부정 캐시, 5xx → 503, JWT/무헤더 요청 무변경, 비밀 미설정 fail-closed.
- myFront: `npm run build`. wiki-front/alm-front: 각 게이트.
- 통합(로컬 컴포즈): 실제 발급 → `curl -H "Authorization: Bearer chanho_pat_…" http://localhost/api/me` 200 → 폐기 → 401. 이 실측을 리뷰 게이트로 삼는다.

## 9. 실행 순서
1. auth-server(모델·관리·교환) ∥ gateway(필터) ∥ myFront(화면) ∥ infra(env) ∥ 문서 — 경계 계약은 이 문서 §3.1·§3.2 로 고정.
2. 리뷰(code-review + platform-integration). Codex 생략(페이블).
3. 푸시 순서: infra-settings → auth-server → gateway-server → myFront → wiki-front/alm-front. 로컬 롤아웃 후 §8 통합 실측.

## 10. 열린 결정(기본값으로 진행)
- 만료 필수(최대 365일). 무기한 토큰은 두지 않는다(아틀라시안도 2024년부터 필수).
- 교환 JWT TTL 300s + 게이트웨이 캐시 60s → 폐기 후 최대 60초 안에 차단된다. 즉시 차단이 필요하면 캐시를 줄인다.
- 사용자당 25개 한도.
