package com.green.java.inflearnsecurity;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.List;
@Component // Bean
@RequiredArgsConstructor
public class CustomAuthenticationProvider implements AuthenticationProvider {
    // Bean으로 정의한 CustomUserDetailsService
    private final UserDetailsService userDetailsService;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        // id와 pw가 함께 들어오는 인증 객체
        String loginId=authentication.getName();
        String password=(String)authentication.getCredentials(); // Object Type

        // 아이디, 비밀번호 검증
        UserDetails user = userDetailsService.loadUserByUsername(loginId);
        // User가 null일 경우 방법 1
        if(user==null){throw new UsernameNotFoundException("User not found");}
        // 새로운 인증 객체
                                                                        // 리스트 타입의 권한(컬렉션 타입)
        return new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword(), user.getAuthorities());
//        return new UsernamePasswordAuthenticationToken(loginId, password, List.of(new SimpleGrantedAuthority("ROLE_USER")));
    }

    @Override
    public boolean supports(Class<?> authentication) {
        // 인증의 요건에 맞게 로직
        // 파라미터의 타입과 메소드의 파라미터 타입이 일치하는지 확인
        return authentication.isAssignableFrom(UsernamePasswordAuthenticationToken.class);
    } // true를 줄 경우 무조건 사용


    /* AuthenticationManager
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        String loginId = authentication.getName();
        String password = (String) authentication.getCredentials();

        return new UsernamePasswordAuthenticationToken(loginId, null, List.of(new SimpleGrantedAuthority("ROLE_USER")));
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.isAssignableFrom(UsernamePasswordAuthenticationToken.class);
    }
     */
}