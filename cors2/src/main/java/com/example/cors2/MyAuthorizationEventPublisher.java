package com.example.cors2;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.authorization.AuthorityAuthorizationDecision;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationEventPublisher;
import org.springframework.security.authorization.event.AuthorizationGrantedEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.function.Supplier;

public class MyAuthorizationEventPublisher implements AuthorizationEventPublisher {
    private final AuthorizationEventPublisher delegate;
    private final ApplicationEventPublisher eventPublisher;

    public MyAuthorizationEventPublisher(AuthorizationEventPublisher delegate, ApplicationEventPublisher eventPublisher) {
        this.delegate = delegate;
        this.eventPublisher = eventPublisher;
    }

    @Override
    public <T> void publishAuthorizationEvent(Supplier<Authentication> authentication,
                                              T object, AuthorizationDecision decision) {
        if (decision == null) {
            return;
        }
        // 인가 실패 -> 이벤트 발행
        if (!decision.isGranted()) {
            this.delegate.publishAuthorizationEvent(authentication, object, decision);
            return;
        }
        // 인가 성공 -> 이벤트 발행
        if (shouldThisEventBePublished(decision)) {
            AuthorizationGrantedEvent<T> granted = new AuthorizationGrantedEvent<>(
                    authentication, object, decision);
            eventPublisher.publishEvent(granted);
        }
    }

    // 성공 이벤트 발행의 조건
                                            // boolean 타입 상수(granted)만 가짐
    private boolean shouldThisEventBePublished(AuthorizationDecision decision) {
                                // granted와 authorities
        if (!(decision instanceof AuthorityAuthorizationDecision)) {
            return false;
        }
                                                    // 현재 권한 목록(엔드포인트와 허용 권한)
        Collection<GrantedAuthority> authorities = ((AuthorityAuthorizationDecision) decision).getAuthorities();
        for (GrantedAuthority authority : authorities) {
            if ("ROLE_ADMIN".equals(authority.getAuthority())) {
                return true;
            }
        }
        return false;
    }
}
