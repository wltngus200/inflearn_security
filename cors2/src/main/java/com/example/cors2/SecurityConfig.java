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
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.XorCsrfTokenRequestAttributeHandler;
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
        // 초기화 되면서 세션에 저장되기 때문에 쿠키로 변경 -> XSRF-TOKEN 이름으로 실림
        CookieCsrfTokenRepository csrfTokenRepository=new CookieCsrfTokenRepository();
        // Repository.set...을 할 경우 파라미터 이름, 쿠키 이름 변경 가능
        // 개발자도구 > Application > Cookies > http://localhost:8080

        // 핸들러
        XorCsrfTokenRequestAttributeHandler csrfTokenRequestAttributeHandler=new XorCsrfTokenRequestAttributeHandler();
        // 요청과 동시에 토큰(지연 X)
        csrfTokenRequestAttributeHandler.setCsrfRequestAttributeName(null);

        http.authorizeHttpRequests(auth->auth
                .requestMatchers("/csrf", "/csrfToken").permitAll()
                .anyRequest().authenticated())
            .formLogin(Customizer.withDefaults())
                                                                        // 스크립트에서 참조 가능
            .csrf(csrf->csrf
//                    .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                    .csrfTokenRequestHandler(csrfTokenRequestAttributeHandler))
        ;

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
