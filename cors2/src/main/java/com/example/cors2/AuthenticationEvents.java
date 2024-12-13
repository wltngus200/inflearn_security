package com.example.cors2;

import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.*;
import org.springframework.security.authorization.event.AuthorizationDeniedEvent;
import org.springframework.security.authorization.event.AuthorizationEvent;
import org.springframework.security.authorization.event.AuthorizationGrantedEvent;
import org.springframework.stereotype.Component;

@Component
public class AuthenticationEvents {
    /* 인증 이벤트 - 인증 이벤트를 수신할 수 있는 클래스
    @EventListener // 어노테이션
                        // 수신하고자하는 이벤트 타입
    public void onSuccess(AuthenticationSuccessEvent success) {
        System.out.println("success = " + success.getAuthentication().getName());
    }

    @EventListener
    public void onFailure(AbstractAuthenticationFailureEvent failures) {
        System.out.println("failures = " + failures.getException().getMessage());
    }

    @EventListener
    public void onSuccess(InteractiveAuthenticationSuccessEvent success) {
        System.out.println("success = " + success.getAuthentication().getName());
    }

    @EventListener // 커스텀 이벤트
    public void onSuccess(CustomAuthenticationSuccessEvent success) {
        System.out.println("success = " + success.getAuthentication().getName());
    }

    @EventListener
    public void onFailure(AuthenticationFailureBadCredentialsEvent failures) {
        System.out.println("failures = " + failures.getException().getMessage());
    }

    @EventListener
    public void onFailure(AuthenticationFailureProviderNotFoundEvent failures) {
        System.out.println("failures = " + failures.getException().getMessage());
    }

    @EventListener
    public void onFailure(CustomAuthenticationFailureEvent failures) {
        System.out.println("failures = " + failures.getException().getMessage());
    }
    */
    /* 인가 이벤트 */
    @EventListener
                                // 인가 이벤트의 상위 클래스
    public void onAuthorization(AuthorizationEvent event){
        System.out.println("event = "+event.getAuthentication().get().getAuthorities());
    }

    @EventListener
    public void onAuthorization(AuthorizationDeniedEvent failure){
        System.out.println("event = "+failure.getAuthentication().get().getAuthorities());
    }

    @EventListener
    public void onAuthorization(AuthorizationGrantedEvent success){
        System.out.println("event = "+success.getAuthentication().get().getAuthorities());
    }
}
