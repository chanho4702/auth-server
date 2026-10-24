-- 리프레시 회전 때 Keycloak 계정·롤 재확인(권한·계정 점검 M1 일부, 2026-10-24).
--
-- roles는 로그인 순간의 스냅샷이었다. 이제 회전마다 Keycloak Admin REST로 다시 맞추고, 마지막으로 맞춘 시각을 남긴다.
-- Keycloak 장애로 확인을 못 할 때 "얼마나 오래된 roles까지 믿을지"(platform.keycloak-sync.max-stale-seconds)를
-- 이 값으로 판단한다. 기존 행은 NULL — 첫 확인 전에 KC가 죽어 있으면 last_login_at을 대신 본다.
ALTER TABLE users ADD COLUMN roles_synced_at TIMESTAMP;
