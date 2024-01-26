package me.aurum.portal.member.controller;

import lombok.extern.slf4j.Slf4j;
import me.aurum.portal.member.domain.Member;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import static me.aurum.login.utils.LoginInfo.getLoginUser;

@Controller
@Slf4j
public class HomeController {

    @GetMapping("/main")
    public String mainPage(Model model) {

        Member loginUser = getLoginUser();

        log.info(" loginUser :: {}", loginUser);
        model.addAttribute("loginUser", loginUser);
        model.addAttribute("account", loginUser.getAccount());
        model.addAttribute("loginType", "SESSION");

        return "main";
    }

    @GetMapping("/login")
    public String login(Model model) {
        /*model.addAttribute("loginType", "session-login");
        model.addAttribute("pageName", "세션 로그인");
        model.addAttribute("loginRequest", new LoginRequest());*/

        return "login-form";
    }

    @GetMapping("/signup")
    public String signUp(Member member) {
        return "signup-form";
    }

    @GetMapping("/user")
    public String user() {
        return "user/index";
    }

    @GetMapping("/test")
    public String test() {
        return "test";
    }


}
