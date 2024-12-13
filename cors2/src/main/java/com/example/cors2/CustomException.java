package com.example.cors2;

import org.springframework.security.core.AuthenticationException;

/* Authentication EventPublisher */
public class CustomException extends AuthenticationException {
    public CustomException(String explanation) {
        super(explanation);
    }
}
