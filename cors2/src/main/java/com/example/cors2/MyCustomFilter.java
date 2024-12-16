package com.example.cors2;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/* Custom DSLs */
// 간단한 인증을 처리
public class MyCustomFilter extends OncePerRequestFilter {
    private boolean flag;

    public void setFlag(boolean flag){
        this.flag=flag;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if(flag){
            try {
                // request는 보안 메소드가 추가된 래퍼클래스 -> 인증 수행 가능
                // 서블릿에서도 인증을 처리할 수 있는 보안 메서드를 가진 request 객체
                String username = request.getParameter("username");
                String password = request.getParameter("password");
                request.login(username, password);
            }catch(Exception e){
                System.out.println(e.getMessage());
            }
        }
        filterChain.doFilter(request, response);
    }
}
