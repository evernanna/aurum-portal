package me.aurum.portal.member.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import me.aurum.login.domain.LoginRequest;
import me.aurum.portal.member.domain.Member;
import me.aurum.security.MemberDetails;
import me.aurum.portal.member.repository.MemberRepository;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
public class MemberDetailsService implements UserDetailsService {

    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        log.info("loadUserByUsername - username :: {}", username);

        Member member = memberRepository.findByAccount(username).orElseThrow(
                () -> new UsernameNotFoundException("Invalid Authentication")
        );

        log.warn("loadUserByUsername - member :: {}", member);

        return new MemberDetails(member);
    }

    /*public User getMemberById(Long id) throws UsernameNotFoundException {

        log.info("getMemberById - id :: {}", id);

        Member member = memberRepository.findById(id).orElseThrow(
                () -> new UsernameNotFoundException("Invalid Authentication")
        );

        log.warn("getMemberById - member :: {}", member);

        return new User(member.getAccount(), member.getPassword(), (Collection<? extends GrantedAuthority>) member.getRoles());
    }*/

    /**
     *  로그인 기능
     *  화면에서 LoginRequest(loginId, password)을 입력받아 loginId와 password가 일치하면 User return
     *  loginId가 존재하지 않거나 password가 일치하지 않으면 null return
     */
    public UserDetails login(LoginRequest request) {
        Optional<Member> optionalUser = memberRepository.findByAccount(request.getAccount());

        // loginId와 일치하는 User가 없으면 null return
        if(!optionalUser.isPresent()) {
            return null;
        }

        MemberDetails memberDetails = new MemberDetails(optionalUser.get());

        // 찾아온 User의 password와 입력된 password가 다르면 null return
        log.info(" memberDetails.getPassword() :: {}", memberDetails.getPassword());
        log.info(" request.getPassword() :: {}", request.getPassword());
        if(!passwordEncoder.matches(request.getPassword(), memberDetails.getPassword())) {
            return null;
        }
        return memberDetails;
    }
}
