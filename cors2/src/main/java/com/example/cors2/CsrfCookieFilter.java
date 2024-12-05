package com.example.cors2;

// 요청에 의해 쿠키를 만들어 렌더링

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class CsrfCookieFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // 지연된 토큰을 가져옴
        CsrfToken csrfToken=(CsrfToken)request.getAttribute("_csrf");
        if(csrfToken!=null){
            csrfToken.getToken(); // 렌더링 -> 내부의 모든 서플라이어가 실행
        }
        filterChain.doFilter(request, response);
    }
}
