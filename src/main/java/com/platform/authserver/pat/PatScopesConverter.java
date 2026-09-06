package com.platform.authserver.pat;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;

import java.util.List;

/**
 * {@code personal_access_tokens.scopes}(쉼표 구분 VARCHAR) ↔ {@code List<String>} 변환.
 * 스코프별 검색·조인이 없어 별도 테이블 대신 한 컬럼으로 두기로 한 결정(V5 주석)의 짝이다.
 *
 * <p>DB로 나갈 때 재정렬하지 않는다 — 정규화는 {@link PatScopes#normalize} 한 곳에서만 하고,
 * 여기서 또 손대면 "저장된 값 그대로"가 깨져 디버깅이 어려워진다.
 */
@Converter
public class PatScopesConverter implements AttributeConverter<List<String>, String> {

    @Override
    public String convertToDatabaseColumn(List<String> attribute) {
        return attribute == null ? "" : PatScopes.join(attribute);
    }

    @Override
    public List<String> convertToEntityAttribute(String dbData) {
        return PatScopes.parse(dbData);
    }
}
