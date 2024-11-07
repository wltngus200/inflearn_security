package com.green.java.inflearnsecurity;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.CurrentSecurityContext;
import org.springframework.security.core.context.SecurityContext;
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

    // 익명 객체
    @GetMapping("/anonymous") // 익명 개체들이 접근 가능하게 설정되어있음
    public String anonymous(){
        return "anonymous";
    }
    @GetMapping("/authentication")
                                // 인증 받은 사용자의 인증객체 or 익명 사용자의 null
    public String authentication(Authentication authentication){
                        // 타입 확인
        if(authentication instanceof AnonymousAuthenticationToken){
            return "anonymous";
        }return "not anonymous";
    }
    // 어노테이션으로 접근 위의 방식으로는 익명객체를 참조할 수 없음
    @GetMapping("/anonymousContext")
    public String anonymousContext(@CurrentSecurityContext SecurityContext context){
        return context.getAuthentication().getName();
    }
}