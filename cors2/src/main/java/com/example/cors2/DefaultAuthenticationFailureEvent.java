package com.example.cors2;

import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

public class DefaultAuthenticationFailureEvent extends AbstractAuthenticationFailureEvent {
    // CustomAuthenticationProvider에서 발생한 예외
    public DefaultAuthenticationFailureEvent(Authentication authentication, AuthenticationException exception) {
        super(authentication, exception);
    }
}
