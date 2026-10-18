-- 계정 비활성(P-02)은 "이 사용자의 미폐기 리프레시 토큰 전부 폐기"(user_id + revoked=false)로 들어온다.
-- user_id 인덱스가 없어 refresh_tokens 전체를 훑었다. 대상은 미폐기 행뿐이라 부분 인덱스로 작게 유지한다
-- (폐기된 옛 행은 재사용 탐지 증거로 가족 수명 동안 쌓인다).
CREATE INDEX idx_refresh_user_active ON refresh_tokens(user_id) WHERE revoked = false;
