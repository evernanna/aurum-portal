package me.aurum.login.service;


import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import me.aurum.login.domain.LoginRequest;
import me.aurum.login.domain.LoginResponse;
import me.aurum.portal.member.domain.Authority;
import me.aurum.portal.member.domain.Member;
import me.aurum.portal.member.repository.MemberRepository;
import me.aurum.security.JwtProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collections;

@Service
@Transactional
@RequiredArgsConstructor
@Slf4j
public class LoginService {

    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtProvider jwtProvider;

    public LoginResponse login(LoginRequest request) throws Exception {
        Member member = memberRepository.findByAccount(request.getAccount()).orElseThrow(() ->
                new BadCredentialsException("잘못된 계정정보입니다."));

        if (!passwordEncoder.matches(request.getPassword(), member.getPassword())) {
            throw new BadCredentialsException("잘못된 계정정보입니다.");
        }

        return LoginResponse.builder()
                .id(member.getId())
                .account(member.getAccount())
                .name(member.getName())
                .email(member.getEmail())
                .roles(member.getRoles())
                .token(jwtProvider.createToken(member.getAccount(), member.getRoles()))
                .build();

    }

    public boolean register(LoginRequest request) throws Exception {
        try {
            Member member = Member.builder()
                    .account(request.getAccount())
                    .password(passwordEncoder.encode(request.getPassword()))
                    .name(request.getName())
                    .email(request.getEmail())
                    .build();

            member.setRoles(Collections.singletonList(Authority.builder().name("ROLE_USER").build()));
            memberRepository.save(member);
        } catch (Exception e) {
            log.error(e.getMessage());
            throw new Exception("잘못된 요청입니다.");
        }
        return true;
    }

    public LoginResponse getMember(String account) throws Exception {
        Member member = memberRepository.findByAccount(account)
                .orElseThrow(() -> new Exception("계정을 찾을 수 없습니다."));
        return new LoginResponse(member);
    }

}