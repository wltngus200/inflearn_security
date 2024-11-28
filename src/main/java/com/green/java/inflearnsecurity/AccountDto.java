package com.green.java.inflearnsecurity;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

// DB로부터 가져온 사용자 정보를 담는 도메인 객체
@Getter
@AllArgsConstructor
public class AccountDto {
    private String userName;
    private String password;
    private Collection<GrantedAuthority> authorities;
}
