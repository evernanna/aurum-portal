package me.aurum.portal.member.controller;

import me.aurum.login.domain.LoginRequest;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class HomeController {


    /*@GetMapping("/")
    public String home() {
        return "home";
    }*/

    @GetMapping("/test")
    public String test() {
        return "test";
    }

    @RequestMapping("/login-form")
    public String login(Model model) {
        model.addAttribute("loginType", "session-login");
        model.addAttribute("pageName", "세션 로그인");

        model.addAttribute("loginRequest", new LoginRequest());

        return "login-form";
    }

    @RequestMapping("/login-success")
    public String loginSuccess() {
        return "login-success";
    }

    @RequestMapping("/user")
    public String user() {
        return "user/index";
    }

}
