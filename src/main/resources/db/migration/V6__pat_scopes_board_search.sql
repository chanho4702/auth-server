-- PAT 스코프에 게시판·검색을 추가한다: board:read board:write search:read.
-- 허용 집합 자체는 애플리케이션(PatScopes.ALL)이 들고 있고 컬럼은 그대로 VARCHAR(255)다
-- (10개를 다 담아도 99자). 스키마 변경 없이 기존 행의 값만 손본다.
--
-- 백필 범위가 이 마이그레이션의 유일한 판단이다.
--
-- V5는 "스코프 개념이 없던 시절의 토큰"을 전체 스코프로 채웠다. 그 토큰들은 그 전까지 게시판·검색을
-- 포함한 모든 경로에 쓰이고 있었는데, V5가 채운 7개에는 board·search가 없어(당시엔 스코프 자체가
-- 없었다) 게이트웨이가 두 경로를 막아버린 상태다. 그 상태를 원래 동작으로 되돌린다.
--
-- 반대로 스코프를 골라 발급한 토큰(예: wiki:read 하나)에는 덧붙이지 않는다. 사용자가 좁히기로
-- 선택한 자격증명에 마이그레이션이 조용히 게시판 쓰기 권한을 얹는 것은 권한 확대다. 넓히는 것은
-- 나중에 새 마이그레이션으로 언제든 할 수 있지만, 이미 넓힌 것은 되돌릴 수 없다.
--
-- 따라서 대상은 "V5가 채운 전체 스코프 문자열 그대로인 행"뿐이다. 결과 문자열은 PatScopes.ALL과
-- 같은 순서·같은 내용이어야 한다(PatScopesTest가 두 문자열을 모두 대조한다).
UPDATE personal_access_tokens
   SET scopes = 'admin,alm:read,alm:write,board:read,board:write,org:read,org:write,search:read,wiki:read,wiki:write'
 WHERE scopes = 'admin,alm:read,alm:write,org:read,org:write,wiki:read,wiki:write';
