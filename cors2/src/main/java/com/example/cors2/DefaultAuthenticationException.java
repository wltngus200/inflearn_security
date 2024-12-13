package com.example.cors2;

import org.springframework.security.core.AuthenticationException;

public class DefaultAuthenticationException extends AuthenticationException {
    // CustomAuthenticationProvider에서 발생한 예외
    public DefaultAuthenticationException(String explanation) {
        super(explanation);
    }
}
