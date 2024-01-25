package me.aurum.login.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import me.aurum.login.domain.LoginRequest;
import me.aurum.login.domain.LoginResponse;
import me.aurum.login.service.LoginService;
import me.aurum.portal.member.repository.MemberRepository;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/login")
@Slf4j
public class LoginRestController {

    private final LoginService loginService;

    @PostMapping(value = "/signin-json")
    public ResponseEntity<LoginResponse> signin(@RequestBody LoginRequest request) throws Exception {

        log.warn("LoginRestController signin request :: {} ", request);

        return new ResponseEntity<>(loginService.login(request), HttpStatus.OK);
    }

    @PostMapping(value = "/signin")
    public ResponseEntity<LoginResponse> signin2(@ModelAttribute LoginRequest request) throws Exception {

        log.warn("LoginRestController signin request.getAccount :: {} ", request.getAccount());
        log.warn("LoginRestController signin request.getPassword :: {} ", request.getPassword());

        return new ResponseEntity<>(loginService.login(request), HttpStatus.OK);
    }

    @PostMapping(value = "/signup")
    public ResponseEntity<Boolean> signup(@RequestBody LoginRequest request) throws Exception {
        return new ResponseEntity<>(loginService.register(request), HttpStatus.OK);
    }

    @GetMapping("/user/get")
    public ResponseEntity<LoginResponse> getUser(@RequestParam String account) throws Exception {
        return new ResponseEntity<>(loginService.getMember(account), HttpStatus.OK);
    }

    @GetMapping("/admin/get")
    public ResponseEntity<LoginResponse> getUserForAdmin(@RequestParam String account) throws Exception {
        return new ResponseEntity<>(loginService.getMember(account), HttpStatus.OK);
    }
}
