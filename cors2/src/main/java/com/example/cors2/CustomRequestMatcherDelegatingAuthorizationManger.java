package com.example.cors2;

import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.security.web.access.intercept.RequestMatcherDelegatingAuthorizationManager;
import org.springframework.security.web.util.matcher.RequestMatcherEntry;

import java.util.List;
import java.util.function.Supplier;

public class CustomRequestMatcherDelegatingAuthorizationManger implements AuthorizationManager<RequestAuthorizationContext> {
    RequestMatcherDelegatingAuthorizationManager manager;

    public CustomRequestMatcherDelegatingAuthorizationManger(List<RequestMatcherEntry<AuthorizationManager<RequestAuthorizationContext>>> mappings){
    // mapping를 활용해 RequestMatcher 타입의 클래스 생성                   // consumer
        manager=RequestMatcherDelegatingAuthorizationManager.builder().mappings(map->map.addAll(mappings)).build();
    }

    @Override
    public AuthorizationDecision check(Supplier<Authentication> authentication, RequestAuthorizationContext object) {
                                        // 리퀘스트 정보
        return manager.check(authentication, object.getRequest());
    }

    @Override
    public void verify(Supplier<Authentication> authentication, RequestAuthorizationContext object) {
        AuthorizationManager.super.verify(authentication, object);
    }
}
