package me.aurum.login.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import me.aurum.portal.member.domain.Authority;
import me.aurum.portal.member.domain.Member;

import java.util.ArrayList;
import java.util.List;

@Getter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class LoginResponse {

    private Long id;
    private String account;
    private String name;
    private String email;
    private List<Authority> roles = new ArrayList<>();

    private String token;

    public LoginResponse(Member member) {
        this.id = member.getId();
        this.account = member.getAccount();
        this.name = member.getName();
        this.email = member.getEmail();
        this.roles = member.getRoles();
    }
}
