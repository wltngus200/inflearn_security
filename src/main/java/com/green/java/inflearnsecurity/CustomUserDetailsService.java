package com.green.java.inflearnsecurity;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.List;

public class CustomUserDetailsService implements UserDetailsService {
    // DaoAuthenticationProvider가 사용
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // User가 null일 경우 방법 2
        // if(user==null){throw new UsernameNotFoundException("User not found");}
        // SecurityConfig의 UserDetailsService Bean 활용
        // UserDetailsService
        // return User.withUsername("user").password("{noop}1111").roles("USER").build();
        AccountDto accountDto=new AccountDto("user", "{noop}1111", List.of(new SimpleGrantedAuthority("ROLE_USER")));
        return new CustomUserDetails(accountDto);
    }
}
