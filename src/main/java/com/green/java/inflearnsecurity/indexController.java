package com.green.java.inflearnsecurity;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class indexController {
    // 서버 기동시 톰캣이 8080 포트로 가동
    @GetMapping("/")
    public String index(){
        // id: user pw: 콘솔창 랜덤 문자열 입력시 인증 됨
        return "index";
    }
}
