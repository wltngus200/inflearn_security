package com.green.java.inflearnsecurity;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

public class CustomUserDetailsService implements UserDetailsService {
    // DaoAuthenticationProvider가 사용
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // User가 null일 경우 방법 2
        // if(user==null){throw new UsernameNotFoundException("User not found");}
        // SecurityConfig의 UserDetailsService Bean 활용
        return User.withUsername("user").password("{noop}1111").roles("USER").build();
    }
}
