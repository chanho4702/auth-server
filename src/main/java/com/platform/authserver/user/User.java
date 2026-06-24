package com.platform.authserver.user;

import jakarta.persistence.*;

import java.time.Instant;
import java.util.Arrays;
import java.util.List;

@Entity
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "keycloak_sub", nullable = false, unique = true)
    private String keycloakSub;

    private String email;
    private String name;

    /** 콤마 구분 문자열로 저장(예: "USER,ADMIN"). */
    @Column(nullable = false)
    private String roles = "";

    private String provider;

    @Column(nullable = false)
    private boolean enabled = true;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @Column(name = "last_login_at")
    private Instant lastLoginAt;

    protected User() {
    }

    public User(String keycloakSub) {
        this.keycloakSub = keycloakSub;
        this.createdAt = Instant.now();
    }

    public List<String> getRoles() {
        if (roles == null || roles.isBlank()) {
            return List.of();
        }
        return Arrays.asList(roles.split(","));
    }

    public void setRoles(List<String> roleList) {
        this.roles = String.join(",", roleList);
    }

    public Long getId() { return id; }
    public String getKeycloakSub() { return keycloakSub; }
    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public String getProvider() { return provider; }
    public void setProvider(String provider) { this.provider = provider; }
    public Instant getLastLoginAt() { return lastLoginAt; }
    public void setLastLoginAt(Instant t) { this.lastLoginAt = t; }
}
