package com.example.cors2;

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
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@EnableWebSecurity
@Configuration
public class SecurityConfig {
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{
        /* CSRF
        http.authorizeHttpRequests(auth->auth
            .anyRequest().permitAll())
        .cors(cors->cors.configurationSource(corsConfigurationSource()));
        */
        /* CSRF 토큰 유지 및 검증 */
        http.authorizeHttpRequests(auth->auth
                .requestMatchers("/csrf").permitAll()
                .anyRequest().authenticated())
            .formLogin(Customizer.withDefaults());

        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        // 설정을 할 객체
        CorsConfiguration configuration=new CorsConfiguration();
        configuration.addAllowedOrigin("http://localhost:8080"); // 출처
        configuration.addAllowedMethod("*"); // GET, POST
        configuration.addAllowedHeader("*");
        configuration.setAllowCredentials(true); // 보안 관련 요소
        configuration.setMaxAge(3600L); // 캐시타임 지정

        // source에 configuration 적용
        UrlBasedCorsConfigurationSource source=new UrlBasedCorsConfigurationSource();
                                        // 경로 패턴 지정
        source.registerCorsConfiguration("/**", configuration);

        return source;
    }

    @Bean
    public UserDetailsService userDetailsService(){
        UserDetails user= User.withUsername("user").password("{noop}1111").roles("USER").build();
        return new InMemoryUserDetailsManager(user);
    }
}
