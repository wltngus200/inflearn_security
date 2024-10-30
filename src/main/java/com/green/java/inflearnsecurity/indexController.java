package com.green.java.inflearnsecurity;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class indexController {
    @GetMapping("/")
    public String index(){
        // id: user pw: 콘솔창 랜덤 문자열 입력시 인증 됨
        return "index";
    }
}
