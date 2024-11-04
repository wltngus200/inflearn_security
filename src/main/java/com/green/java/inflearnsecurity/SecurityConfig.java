package com.green.java.inflearnsecurity;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity // Security 설정을 위함
@Configuration // Bean 어노테이션을 위함
public class SecurityConfig {
    // 반드시 1개 이상의 Bean이 필요 + 리턴 타입은 SecurityFilterChain
    @Bean
                                                                    // authorizeHttpRequests의 예외처리
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{
        // 요청 객체를 받아서 인증, 인가 설정
            // http 통신에 대한 인가 정책을 설정함을 의미
        http.authorizeHttpRequests(auth->auth.anyRequest().authenticated())
                // 인증을 받지 못 했을 때의 인증 방식 form Login
                .formLogin(Customizer.withDefaults());
                        // 기본 디폴트로 처리
        return http.build();
        // SpringBootWebSecurityConfiguration로 지나가지 않음
        // ConditionalOnWebApplication 어노테이션 -> DefaultWebSecurityCondition의 SecurityFilterChain이 존재하지 않는다는 메소드가 성립 X
    }

    // 초기화시 작성되는 최초의 계정 작성 -> yaml과 겹쳤을 때에는 클래스가 우선
    @Bean
    // User UserDetailService InMemoryUserDetailsManager
    public UserDetailsService userDetailsService(){
        // 스프링 시큐리티의 내부적으로 가지는 객체
        UserDetails user=User.withUsername("user")
                            .password("{noop}1111")
                            // ROLE이 없어야 함
                            .roles("USER")
                            .build();
        UserDetails user2=User.withUsername("user2")
                .password("{noop}1111")
                .roles("USER")
                .build();
        UserDetails user3=User.withUsername("user3")
                .password("{noop}1111")
                .roles("USER")
                .build();
        return new InMemoryUserDetailsManager(user, user2, user3);

    // http://localhost:8080/login?logout 로그인 된 계정 로그아웃 링크
    }
}
