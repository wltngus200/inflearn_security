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
    // 모든 요청에 대해 인증을 거쳐야 함 -> 인증이 안 된 사용자 form로그인 -> 우리가 커스텀한 로그인 페이지
    // 즉, SecurityConfig에서 form.loginPage()의 url값과 동일해야 함
    @GetMapping("/loginPage")
    public String loginPage(){
        // 뷰, HTML 렌더링 설정 X
        return "login page";
    }
    @GetMapping("/home")
    public String home(){
        return "login success";
    }
}
