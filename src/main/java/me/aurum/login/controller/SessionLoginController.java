package me.aurum.login.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import me.aurum.login.domain.LoginRequest;
import me.aurum.portal.member.service.MemberDetailsService;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import org.thymeleaf.spring5.context.SpringContextUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

@Controller
@RequiredArgsConstructor
@RequestMapping("/session-login")
@Slf4j
public class SessionLoginController {

    private final MemberDetailsService memberDetailsService;

    @GetMapping(value = {"", "/"})
    public String home(Model model, @SessionAttribute(name = "username", required = false) String username) {
        model.addAttribute("loginType", "session-login");
        model.addAttribute("pageName", "세션 로그인");

        UserDetails userDetails = memberDetailsService.loadUserByUsername(username);

        if(userDetails != null) {
            model.addAttribute("nickname", userDetails.getUsername()); // TODO name
        }

        return "home";
    }

    /*@GetMapping("/join")
    public String joinPage(Model model) {
        model.addAttribute("loginType", "session-login");
        model.addAttribute("pageName", "세션 로그인");

        model.addAttribute("joinRequest", new JoinRequest());
        return "join";
    }*/

    /*@PostMapping("/join")
    public String join(@Valid @ModelAttribute JoinRequest joinRequest, BindingResult bindingResult, Model model) {
        model.addAttribute("loginType", "session-login");
        model.addAttribute("pageName", "세션 로그인");

        // loginId 중복 체크
        if(memberDetailsService.checkLoginIdDuplicate(joinRequest.getLoginId())) {
            bindingResult.addError(new FieldError("joinRequest", "loginId", "로그인 아이디가 중복됩니다."));
        }
        // 닉네임 중복 체크
        if(memberDetailsService.checkNicknameDuplicate(joinRequest.getNickname())) {
            bindingResult.addError(new FieldError("joinRequest", "nickname", "닉네임이 중복됩니다."));
        }
        // password와 passwordCheck가 같은지 체크
        if(!joinRequest.getPassword().equals(joinRequest.getPasswordCheck())) {
            bindingResult.addError(new FieldError("joinRequest", "passwordCheck", "바밀번호가 일치하지 않습니다."));
        }

        if(bindingResult.hasErrors()) {
            return "join";
        }

        memberDetailsService.join(joinRequest);
        return "redirect:/session-login";
    }*/

    @GetMapping("/login")
    public String loginPage(Model model) {
        model.addAttribute("loginType", "session-login");
        model.addAttribute("pageName", "세션 로그인");

        model.addAttribute("loginRequest", new LoginRequest());
        return "login";
    }

    @PostMapping("/login")
    public String login(@ModelAttribute LoginRequest loginRequest, BindingResult bindingResult,
                        HttpServletRequest httpServletRequest, Model model) {
        model.addAttribute("loginType", "session-login");
        model.addAttribute("pageName", "세션 로그인");

        log.info("login loginRequest :: {}", loginRequest);

        UserDetails login = memberDetailsService.login(loginRequest);

        log.info("login loginRequest :: {}", loginRequest);

        // 로그인 아이디나 비밀번호가 틀린 경우 global error return
        if(login == null) {
            bindingResult.reject("loginFail", "로그인 아이디 또는 비밀번호가 틀렸습니다.");
        }

        if(bindingResult.hasErrors()) {
            return "login-form";
        }

        // 로그인 성공 => 세션 생성

        // 세션을 생성하기 전에 기존의 세션 파기
        httpServletRequest.getSession().invalidate();
        HttpSession session = httpServletRequest.getSession(true);  // Session이 없으면 생성
        
        // TODO SPRING CONTEXTHOLDER 추가
        
        // 세션에 userId를 넣어줌
        session.setAttribute("username", login.getUsername());
        session.setMaxInactiveInterval(1800); // Session이 30분동안 유지

        return "redirect:/session-login";
    }

    @GetMapping("/logout")
    public String logout(HttpServletRequest request, Model model) {
        model.addAttribute("loginType", "session-login");
        model.addAttribute("pageName", "세션 로그인");

        HttpSession session = request.getSession(false);  // Session이 없으면 null return
        if(session != null) {
            session.invalidate();
        }
        return "redirect:/session-login";
    }

    @GetMapping("/info")
    public String userInfo(@SessionAttribute(name = "userId", required = false) Long userId, Model model, Authentication authentication) {
        model.addAttribute("loginType", "session-login");
        model.addAttribute("pageName", "세션 로그인");

        if(authentication == null) {
            log.error(" authentication :: IS NULL");
            return "redirect:/session-login/login";
        }

        UserDetails loginUser = (UserDetails) authentication.getPrincipal();

        if(loginUser == null) {
            log.error(" loginUser :: IS NULL");
            return "redirect:/session-login/login";
        }

        model.addAttribute("user", loginUser);
        return "user/info";
    }

    /*@GetMapping("/admin")
    public String adminPage(@SessionAttribute(name = "userId", required = false) Long userId, Model model) {
        model.addAttribute("loginType", "session-login");
        model.addAttribute("pageName", "세션 로그인");

        User loginUser = memberDetailsService.getLoginUser(userId);

        if(loginUser == null) {
            return "redirect:/session-login/login";
        }

        if(!loginUser.getRole().equals(UserRole.ADMIN)) {
            return "redirect:/session-login";
        }

        return "admin";
    }*/
}