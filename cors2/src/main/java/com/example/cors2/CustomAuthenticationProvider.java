package com.example.cors2;

import lombok.RequiredArgsConstructor;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.event.AuthenticationFailureProviderNotFoundEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

// @Component // Bean으로 설정되면 자동으로 추가됨
// @RequiredArgsConstructor
public class CustomAuthenticationProvider implements AuthenticationProvider {

    // private final ApplicationContext applicationEventPublisher;

    @Override // 인증 수행
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        // 인증 주체가 user가 아닐 경우 실패 이벤트 발생
        if(!authentication.getName().equals("user")) {
//            applicationEventPublisher.publishEvent
//                        // 시큐리티가 가진 이벤트 AuthenticationFailureBadCredentialsEvent
//                    (new AuthenticationFailureProviderNotFoundEvent(authentication, new BadCredentialsException("BadCredentialException")));
            // 이벤트 발생 후 예외
            throw new BadCredentialsException("BadCredentialsException");
        }

        UserDetails user = User.withUsername("user").password("{noop}1111").roles("USER").build();
        return new UsernamePasswordAuthenticationToken(user, user.getPassword(), user.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return true;
    }
}
