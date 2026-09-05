-- 개인 API 토큰(PAT). 원문은 저장하지 않고 SHA-256 해시만 남긴다
-- (RefreshTokenService.sha256 재사용 — base64url 43자. hex 64자가 아니므로 VARCHAR(64)로 충분).
-- 시각 컬럼은 V1/V3의 refresh_tokens와 같은 TIMESTAMP를 쓴다 — Instant 매핑이 이미 이 타입으로
-- ddl-auto=validate를 통과하고 있어 여기서만 TIMESTAMPTZ로 갈라놓지 않는다.
CREATE TABLE personal_access_tokens (
    id           UUID PRIMARY KEY,
    user_id      BIGINT NOT NULL REFERENCES users(id),
    label        VARCHAR(100) NOT NULL,
    token_hash   VARCHAR(64) NOT NULL UNIQUE,
    token_hint   VARCHAR(8) NOT NULL,
    created_at   TIMESTAMP NOT NULL,
    expires_at   TIMESTAMP NOT NULL,
    last_used_at TIMESTAMP,
    revoked_at   TIMESTAMP
);

-- 목록 조회(본인 것만, 최신순)와 활성 개수 한도 검사가 모두 user_id로 들어온다.
CREATE INDEX idx_pat_user ON personal_access_tokens(user_id);
