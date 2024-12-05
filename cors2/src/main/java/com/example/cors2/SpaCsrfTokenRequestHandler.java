package com.example.cors2;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.web.csrf.CsrfTokenRequestHandler;
import org.springframework.security.web.csrf.XorCsrfTokenRequestAttributeHandler;
import org.springframework.util.StringUtils;


import java.util.function.Supplier;

public class SpaCsrfTokenRequestHandler extends CsrfTokenRequestAttributeHandler {
    // CsrfTokenRequestHandler의 구현체 두 가지의 역할을 모두 겸함
    // 담긴 위치로 구분 -> JS는 쿠키로부터 토큰을 읽어옴(쿠키는 생성, 렌더링 시 인코딩 X 원본 값)

    private final CsrfTokenRequestHandler delegate=new XorCsrfTokenRequestAttributeHandler();

    @Override // 호출
    public void handle(HttpServletRequest request, HttpServletResponse response, Supplier<CsrfToken> deferredCsrfToken) {
        delegate.handle(request, response, deferredCsrfToken);
    }

    @Override
    public String resolveCsrfTokenValue(HttpServletRequest request, CsrfToken csrfToken) {
                    // 값이 있는 지(요청 헤더(토큰의 헤더네임))
        if(StringUtils.hasText(request.getHeader(csrfToken.getHeaderName()))){
            // CsrfTokenRequestAttributeHandler - 원본 값 처리 -> request에 Header에 값이 담김
            return super.resolveCsrfTokenValue(request, csrfToken);
        }
        // XorCsrfTokenRequestAttributeHandler - 인코딩 된 값 처리 -> 나머지
        return delegate.resolveCsrfTokenValue(request, csrfToken);
    }


}
