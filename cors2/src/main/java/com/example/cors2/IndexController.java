package com.example.cors2;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
//@RequestMapping("/api")
public class IndexController {
    @GetMapping("/")
    public Authentication index(Authentication authentication){
        return authentication;
    }

    @GetMapping("/users")
    public String users(){
        // Json 형식
        return "{\"name\": \"hong gil-dong\"}";
    }
    // 서블릿 MVC에서 토큰을 가져와 사용
    // 필터가 세션에 저장하기 전에 지연된 객체를 request 객체에 저장(토큰 이름, 문자열)
    @GetMapping("/csrfToken")
    public String csrfToken(HttpServletRequest request){
        // 실제 토큰이 아닌 진짜 토큰을 가진 객체를 실행시키기 위한 지연된 객체
        CsrfToken csrfToken1=(CsrfToken)request.getAttribute(CsrfToken.class.getName());
        CsrfToken csrfToken2=(CsrfToken)request.getAttribute("_csrf");

        // supplier를 호출해 세션으로부터 객체를 가져오거나 새로 생성하고 토큰값 리턴
        String token=csrfToken1.getToken();
        return token;
    }

    @PostMapping("/csrf")
    public String csrf(){
        return "csrf 적용";
    }

    /* CSRF 통합 */
    @PostMapping("/formCsrf")
    public CsrfToken formCsrf(CsrfToken csrfToken){
                            // 자동적으로 현재 생성된 CSRF 토큰 객체 반영
        return csrfToken;
    }

    // cookie.html의 메소드
    @PostMapping("/cookieCsrf")
    public CsrfToken cookieCsrf(CsrfToken csrfToken){
                            // 자동적으로 현재 생성된 CSRF 토큰 객체 반영
        return csrfToken;
    }
}
