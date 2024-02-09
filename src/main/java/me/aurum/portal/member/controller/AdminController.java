package me.aurum.portal.member.controller;

import lombok.extern.slf4j.Slf4j;
import me.aurum.portal.member.domain.Member;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import static me.aurum.login.utils.LoginInfo.getLoginUser;

@Controller
@Slf4j
@RequestMapping("/admin")
public class AdminController {

    @GetMapping("/signup")
    public String signUp(Member member) {
        return "admin/signup-form";
    }

    @GetMapping("/test")
    public String test(Member member) {
        return "admin/test";
    }

}
