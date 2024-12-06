package com.example.cors2;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.web.util.matcher.RequestMatcher;

public class CustomRequestMatcher implements RequestMatcher {
    // 패턴을 만들고 서로 포함관계인지 확인 -> Bean으로 할 필요 X
    private final String urlPattern;

    public CustomRequestMatcher(String urlPattern){
        this.urlPattern=urlPattern;
    }

    @Override
    public boolean matches(HttpServletRequest request) {
        String requestUri=request.getRequestURI();
        return requestUri.startsWith(urlPattern);
    }

}
