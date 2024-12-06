package com.example.cors2;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

// 표현식에 사용될 빈(빈 이름)
@Component("customWebSecurity")
public class CustomWebSecurity {
    public boolean check(Authentication authentication, HttpServletRequest request){
        // 인증 받았는지 확인
        return authentication.isAuthenticated();
    }

}
