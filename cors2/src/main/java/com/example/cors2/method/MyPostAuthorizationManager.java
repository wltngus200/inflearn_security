package com.example.cors2.method;

import com.example.cors2.Account;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.method.MethodInvocationResult;
import org.springframework.security.core.Authentication;

import java.util.function.Supplier;

/* Custom AuthorizationManager */
public class MyPostAuthorizationManager implements AuthorizationManager<MethodInvocationResult> {
    @Override
    public AuthorizationDecision check(Supplier<Authentication> authentication, MethodInvocationResult object) {
        // 결괏값에 따라 판별
        Authentication auth=authentication.get();
        // 익명 사용자
        if (auth instanceof AnonymousAuthenticationToken) {
            return new AuthorizationDecision(false);
        }
        // object는 result를 가짐
        Account account=(Account) object.getResult();
        Boolean isGranted=account.getOwner().equals(auth.getName());
        return new AuthorizationDecision(isGranted);
    }
}
