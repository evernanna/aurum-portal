package me.aurum.define;

import lombok.Getter;

@Getter
public enum UserAuthority {
    ROLE_MASTER("MASTER", "ROLE_MASTER", "마스터"),
    ROLE_ADMIN("ADMIN", "ROLE_ADMIN","관리자"),
    ROLE_USER("USER", "ROLE_USER","사용자");

    private final String code;
    private final String role;
    private final String name;

    UserAuthority(String code, String role,String name) {
        this.code = code;
        this.role = role;
        this.name = name;
    }
}
