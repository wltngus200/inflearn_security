package com.example.cors2;

import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

/* 인증 이벤트 */
public class CustomAuthenticationFailureEvent  extends AbstractAuthenticationFailureEvent {
    public CustomAuthenticationFailureEvent(Authentication authentication, AuthenticationException exception) {
        super(authentication, exception);
    }
}
