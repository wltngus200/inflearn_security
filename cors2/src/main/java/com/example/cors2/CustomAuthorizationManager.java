package com.example.cors2;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

import java.util.function.Supplier;

public class CustomAuthorizationManager implements AuthorizationManager<RequestAuthorizationContext> {

    private static final String REQUIRED_ROLE="ROLE_SECURE";

    @Override
    public AuthorizationDecision check(Supplier<Authentication> authentication, RequestAuthorizationContext object) {
        // 인증 객체 얻어오기
        Authentication auth=authentication.get();
        if(auth==null||!auth.isAuthenticated()||auth instanceof AnonymousAuthenticationToken){
            return new AuthorizationDecision(false);
        }
        // 조건을 통과 = 인증 받음 -> 권한 확인
        boolean hasRequiredRole=auth.getAuthorities().stream().anyMatch(grantedAuthority->REQUIRED_ROLE.equals(grantedAuthority.getAuthority()));
        return new AuthorizationDecision(hasRequiredRole);
    }

   // verify는 디폴트이기 때문에 반드시 정의하지 않아도 됨
}
