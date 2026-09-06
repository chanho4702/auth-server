-- PAT 스코프. 토큰 하나가 어떤 제품/동작에 쓰일 수 있는지를 담는다 — 강제는 게이트웨이
-- (PatScopeWebFilter)가 교환 JWT의 scope 클레임을 보고 하고, auth-server는 발급·저장·전달만 한다.
--
-- 쉼표 구분 문자열 한 컬럼으로 둔다(별도 테이블 아님): 값 집합이 7개로 고정이고 개별 스코프로
-- 검색·조인할 일이 없다. 정렬·중복 제거는 애플리케이션(PatScopes.normalize)이 보장한다.
-- 전체 7개를 다 담아도 64자라 VARCHAR(255)면 충분하다.
ALTER TABLE personal_access_tokens ADD COLUMN scopes VARCHAR(255);

-- 기존 행 백필: 스코프 개념이 없던 시절에 발급된 토큰은 모든 경로에 쓰이고 있었으므로
-- 전체 스코프를 준다(현재 동작 유지 — 여기서 좁히면 이미 돌고 있는 CI/스크립트가 깨진다).
-- 이 목록은 PatScopes.ALL과 같은 순서·같은 내용이어야 한다(PatScopesTest가 대조한다).
UPDATE personal_access_tokens
   SET scopes = 'admin,alm:read,alm:write,org:read,org:write,wiki:read,wiki:write'
 WHERE scopes IS NULL;

ALTER TABLE personal_access_tokens ALTER COLUMN scopes SET NOT NULL;
