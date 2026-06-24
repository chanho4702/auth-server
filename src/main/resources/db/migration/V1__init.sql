CREATE TABLE users (
    id            BIGSERIAL PRIMARY KEY,
    keycloak_sub  VARCHAR(255) NOT NULL UNIQUE,
    email         VARCHAR(255),
    name          VARCHAR(255),
    roles         VARCHAR(1000) NOT NULL DEFAULT '',
    provider      VARCHAR(50),
    enabled       BOOLEAN NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMP NOT NULL,
    last_login_at TIMESTAMP
);

CREATE TABLE refresh_tokens (
    id           UUID PRIMARY KEY,
    user_id      BIGINT NOT NULL REFERENCES users(id),
    token_hash   VARCHAR(255) NOT NULL UNIQUE,
    family_id    UUID NOT NULL,
    replaced_by  UUID,
    kc_id_token  TEXT,
    expires_at   TIMESTAMP NOT NULL,
    revoked      BOOLEAN NOT NULL DEFAULT FALSE,
    created_at   TIMESTAMP NOT NULL
);

CREATE INDEX idx_refresh_family ON refresh_tokens(family_id);
