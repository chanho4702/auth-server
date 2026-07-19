package com.platform.authserver.user;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;
import java.util.Arrays;
import java.util.List;

@Entity
@Table(name = "users")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED) // JPA 전용 기본 생성자
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "keycloak_sub", nullable = false, unique = true)
    private String keycloakSub;

    @Setter
    private String email;
    @Setter
    private String name;

    /** 콤마 구분 문자열로 저장(예: "USER,ADMIN"). */
    @Column(nullable = false)
    private String roles = "";

    @Setter
    private String provider;

    @Setter
    @Column(nullable = false)
    private boolean enabled = true;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @Setter
    @Column(name = "last_login_at")
    private Instant lastLoginAt;

    public User(String keycloakSub) {
        this.keycloakSub = keycloakSub;
        this.createdAt = Instant.now();
    }

    /** roles 컬럼은 콤마 구분 문자열이라 List 변환은 수동 유지(Lombok @Getter/@Setter 미적용). */
    public List<String> getRoles() {
        if (roles == null || roles.isBlank()) {
            return List.of();
        }
        return Arrays.asList(roles.split(","));
    }

    public void setRoles(List<String> roleList) {
        this.roles = String.join(",", roleList);
    }
}
