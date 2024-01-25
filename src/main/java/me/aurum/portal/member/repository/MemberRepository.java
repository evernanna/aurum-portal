package me.aurum.portal.member.repository;


import me.aurum.portal.member.domain.Member;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface MemberRepository extends JpaRepository<Member, Long> {

    //Member save(Member member);

    Optional<Member> findById(Long id);

    Optional<Member> findByAccount(String account);
    Optional<Member> findByEmail(String email);

    Optional<Member> findByName(String name);

    List<Member> findAll();

    boolean existsByAccount(String account);
    boolean existsByName(String name);
}
