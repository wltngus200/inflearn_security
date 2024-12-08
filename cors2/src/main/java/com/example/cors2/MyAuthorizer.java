package com.example.cors2;

import org.springframework.security.access.expression.method.MethodSecurityExpressionOperations;
import org.springframework.stereotype.Component;

@Component("myAuthorizer") // 빈 이름
public class MyAuthorizer {
    public boolean isUser(MethodSecurityExpressionOperations root){
        boolean decision=root.hasAuthority("ROLE_USER");
        return decision;
    }
}
