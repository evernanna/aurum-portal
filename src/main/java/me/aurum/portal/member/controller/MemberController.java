package me.aurum.portal.member.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import me.aurum.login.domain.LoginRequest;
import me.aurum.portal.member.service.MemberDetailsService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@Slf4j
@RequestMapping("/member")
public class MemberController {

    private final MemberDetailsService memberDetailsService;

    @PostMapping(value = "/signup")
    public ResponseEntity<Boolean> signup(@RequestBody LoginRequest request) throws Exception {
        return new ResponseEntity<>(memberDetailsService.register(request), HttpStatus.OK);
    }
}
