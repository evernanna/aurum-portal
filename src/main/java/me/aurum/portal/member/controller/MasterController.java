package me.aurum.portal.member.controller;

import lombok.extern.slf4j.Slf4j;
import me.aurum.portal.member.domain.Member;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@Slf4j
@RequestMapping("/master")
public class MasterController {

    @GetMapping("/test")
    public String test(Member member) {
        return "master/test";
    }

}
