package me.aurum.login.utils;

import me.aurum.portal.member.domain.Member;
import me.aurum.security.MemberDetails;
import org.springframework.security.core.context.SecurityContextHolder;

public class LoginInfo {

    public static MemberDetails getLoginDetails() {
        return (MemberDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
    }

    public static Member getLoginUser() {
        return getLoginDetails().getMember();
    }

}
