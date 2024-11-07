package com.green.java.inflearnsecurity;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.boot.util.Instantiator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;

@EnableWebSecurity // Security 설정을 위함
@Configuration // Bean 어노테이션을 위함
public class SecurityConfig {
    // 반드시 1개 이상의 Bean이 필요 + 리턴 타입은 SecurityFilterChain
    @Bean
                                                                    // authorizeHttpRequests의 예외처리
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{
        // 요청 객체를 받아서 인증, 인가 설정
            // http 통신에 대한 인가 정책을 설정함을 의미
        http.authorizeHttpRequests(auth->auth
                        .requestMatchers("/anonymous").hasRole("GUEST")
                        // 익명 사용자를 참조
                        .requestMatchers("/anonymousContext","/authentication").permitAll()
                        // 익명 사용자의 Authentication에는 null
                        .anyRequest().authenticated())
                // 인증을 받지 못 했을 때의 인증 방식 form Login
                .formLogin(Customizer.withDefaults()) // 기본 디폴트로 처리
                         // Customizer 인터페이스 -> 우리가 원하는 대로 작성하고자 할 때 T 제네릭 객체를 받아 커스터마이징, 작성할 게 없다면 withDefaults 메소드
                .anonymous(anonymous->anonymous
                        .principal("guest") // 사용자 이름
                        .authorities("ROLE_GUEST") // 권한
                        // 권한에 따라 접근 할 수 있는 자원
                        );
                /* 인증 기억
                .rememberMe(rememberMe->rememberMe
                                            .alwaysRemember((true)) // 항상 자동로그인 활성화
                                            .tokenValiditySeconds(3600) // 생존 시간
                                            .userDetailsService(userDetailsService()) // 사용자 정보 -> 아래의 정보 활용
                                            .rememberMeParameter("remember")
                                            .rememberMeCookieName("remember")
                                            .key("security")
                );
                 */

                /* ~ httpBasic
                                // 우리가 원하는 API 작성
                .httpBasic(basic->basic.
                        authenticationEntryPoint(new CustomAuthenticationEntryPoint()) // 인증을 받지 못 한 채로 다시 인증을 받게끔 (BasicAuthenticationEntryPoint)
                );
                 */

        /* ~form Login 부분 브랜치에서 확인 가능
                .formLogin(form->form
                                // 로그인 페이지가 나타나야 기능을 사용할 수 있기 때문에 주석
//                                .loginPage("/loginPage") // 로그인을 제공하는 페이지 커스터마이징 -> 현재는 HTML파일 X
                                // form 태그의 action
                                .loginProcessingUrl("/loginProc") // 사용자 정보 검증 url 경로
                                                               // root로 이동
                                .defaultSuccessUrl("/",true) // 로그인 성공시 이동 경로
                                                                    // false로 설정할 시 경우에 따라 다른 경로로 이동
                                                                    // ex. /home에 접속해서 로그인 과정을 거치면 /home으로 이동
                                                                    // 인증을 받기 전 인증이 필요한 요청을 했을 경우 인증 성공 후 해당 요청의 경로로 이동
                                .failureUrl("/failed") // 로그인 실패시 이동 url
                                // 시큐리티 제공의 HTML form 태그 확인
                                // Spring : form 태그의 name을 볼 것 -> 스프링 시큐리티가 화면을 만들면서 우리가 설정한 API값을 가져와 만듦
                                // 우리가 로그인 페이지를 커스텀한다면 아래 값과 form 태그의 name 값을 일치 시켜줘야 작동함
                                .usernameParameter("userId") // username을 찾는 input태그 name속성
                                .passwordParameter("passwd") // password를 찾는 input태그 name속성
                                               // 익명 클래스 -> 람다식도 가능
                                // 성공과 실패 후 작업의 처리
                         주석의 이유 : defaultSuccessUrl,failureUrl 또한 우리가 보기 쉽게 하기 위함이지 내부적으로는 아래의 handler들이 처리, 커스텀할 경우 우리가 정의한 것이 더 우선시 됨(덮어쓰기 효과)
                                .successHandler(new AuthenticationSuccessHandler() {
                                    @Override
                                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                                       System.out.println("authentication : "+ authentication);
                                       // 어디로 이동할지를 작성
                                       response.sendRedirect("/home"); // defaultSuccessUrl는 루트로 이동
                                    }
                                })
                                                                   // 예외가 발생했을 경우에 처리
                                .failureHandler((request, response, exception)->{
                                       System.out.println("exception : "+exception.getMessage());
                                       response.sendRedirect("/login");
                                })
                                // 핸들러의 사용 : 파라미터를 세세하게 조작하여 원하는 후속작업을 원활하게 하기 위함
                                .permitAll()
                                // 로그인 페이지로 갈 수 있는 컨트롤러 속성
                );
        */
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
//        UserDetails user2=User.withUsername("user2")
//                .password("{noop}1111")
//                .roles("USER")
//                .build();
//        UserDetails user3=User.withUsername("user3")
//                .password("{noop}1111")
//                .roles("USER")
//                .build();
        return new InMemoryUserDetailsManager(user);

    // http://localhost:8080/login?logout 로그인 된 계정 로그아웃 링크
    }
}
