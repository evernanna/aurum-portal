package me.aurum.login.domain;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import java.io.Serializable;

@Getter @Setter
@ToString
public class LoginRequest implements Serializable {
    //private Long id;
    private String account;
    private String password;
    private String name;
    private String email;
    private String authority;
}
