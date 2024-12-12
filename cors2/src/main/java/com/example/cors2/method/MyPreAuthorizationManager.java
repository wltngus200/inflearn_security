package com.example.cors2.method;

import org.aopalliance.intercept.MethodInvocation;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;

import java.util.function.Supplier;

/* Custom AuthorizationManager */
public class MyPreAuthorizationManager implements AuthorizationManager<MethodInvocation> {
    @Override
    public AuthorizationDecision check(Supplier<Authentication> authentication, MethodInvocation object) {
        // 인증한 사용자만 메소드에 진입
        Authentication auth = authentication.get();
        // 익명 사용자
        if (auth instanceof AnonymousAuthenticationToken) {
            return new AuthorizationDecision(false);
        }
        return new AuthorizationDecision(auth.isAuthenticated());
    }
}
