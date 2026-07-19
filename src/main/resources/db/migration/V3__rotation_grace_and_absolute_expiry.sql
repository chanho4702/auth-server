-- replaced_at: rotate 선점 시각 — grace period(경쟁 vs 도난) 판정 기준
ALTER TABLE refresh_tokens ADD COLUMN replaced_at TIMESTAMP;

-- family_created_at: 가족 최초 생성 시각 — sliding 만료 보완용 절대 세션 상한 기준
ALTER TABLE refresh_tokens ADD COLUMN family_created_at TIMESTAMP;

-- 기존 행 백필: 가족별 최초 생성 시각
UPDATE refresh_tokens rt SET family_created_at = f.min_created
FROM (SELECT family_id, MIN(created_at) AS min_created
      FROM refresh_tokens GROUP BY family_id) f
WHERE rt.family_id = f.family_id;

ALTER TABLE refresh_tokens ALTER COLUMN family_created_at SET NOT NULL;
