package com.green.java.inflearnsecurity;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.boot.util.Instantiator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AnonymousAuthenticationProvider;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.io.IOException;
import java.util.List;

@EnableWebSecurity // Security 설정을 위함
@Configuration // Bean 어노테이션을 위함
public class SecurityConfig {
    // 반드시 1개 이상의 Bean이 필요 + 리턴 타입은 SecurityFilterChain
    @Bean
    // authorizeHttpRequests의 예외처리
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{
                                                    //, AuthenticationManagerBuilder builder, AuthenticationConfiguration configuration
        /* 인증 아키텍쳐 -요청 캐시
        HttpSessionRequestCache requestCache=new HttpSessionRequestCache();
        requestCache.setMatchingRequestParameterName("customParam=y");
        */
        /* AuthenticationManager 방법 1
        // 초기화를 통해 생성된 AuthenticationManager를 HttpSecurity에 저장되어있는 AuthenticationManagerBuilder를 통해 참조
        AuthenticationManagerBuilder builder=http.getSharedObject(AuthenticationManagerBuilder.class);
        AuthenticationManager authenticationManager=builder.build();
        // build 이후 다른 곳에서 AuthenticationManager를 가져온다면 build X
        AuthenticationManager authenticationManager2=builder.getObject();


        http.authorizeHttpRequests(auth->auth
                        .requestMatchers("/", "/api/login").permitAll()
                        .anyRequest().authenticated())
                .authenticationManager(authenticationManager)
                .addFilterBefore(customAuthenticationFilter(http, authenticationManager), UsernamePasswordAuthenticationFilter.class);
         */
        /*  AuthenticationManager 방법 2 : 직접 ProviderManager를 만듦 */
        /* AuthenticationProvider 추가 방법 1 : 일반 객체로 생성
        AuthenticationManagerBuilder builder=http.getSharedObject(AuthenticationManagerBuilder.class);
        builder.authenticationProvider(new CustomAuthenticationProvider());
        builder.authenticationProvider(new CustomAuthenticationProvider2());*/

        /* AuthenticationProvider 방법 2
        AuthenticationManagerBuilder managerBuilder=http.getSharedObject(AuthenticationManagerBuilder.class); // 시큐리티가 가진 Builder
        managerBuilder.authenticationProvider(authenticationProvider()); // AnonymousAuthenticationProvider 위에 추가
        // 부모 역할을 하는 AuthenticationProvider에는 Custom이 올라가 있음 -> Dao 대체
        ProviderManager authenticationManager=(ProviderManager)configuration.getAuthenticationManager();
        authenticationManager.getProviders().remove(0);
        builder.authenticationProvider(new DaoAuthenticationProvider());
         */
        /* AuthenticationManagerBuilder
        AuthenticationManagerBuilder builder=http.getSharedObject(AuthenticationManagerBuilder.class);
        builder.authenticationProvider(authenticationProvider());
        builder.authenticationProvider(authenticationProvider2());
        */

        /* SecurityContextRepository SecurityContextHolderFilter
        // 커스텀 필터를 사용하기 위해서 AuthenticationManager 필요 + 추가적 설정
        AuthenticationManagerBuilder builder=http.getSharedObject(AuthenticationManagerBuilder.class);
        AuthenticationManager authenticationManager=builder.build();

        http.authorizeHttpRequests(auth->auth
                                            .requestMatchers("/login").permitAll() // 모든 사용자 접근 가능
                                            .anyRequest().authenticated())
                                            // 폼 방식의 인증을 처리하는 필터가 요청을 가로채기때문에 주석
                                            //.formLogin(Customizer.withDefaults())
                                            // post, deletem, put에는 csrf 토큰 값 요구 -> 스프링 시큐리티가 자동으로 만들어서 클라이언트에게 제공(클라이언트는 요청시 가지고 와야 함)
                                            .csrf(csrf->csrf.disable())
                // SecurityContextRepository SecurityContextHolderFilter 영속성 문제 -> 기본 값이 true이기 때문에 발생(false일 경우 자동으로 세션에 저장)
                .securityContext(securityContext->securityContext.requireExplicitSave(false))
                .authenticationManager(authenticationManager)
                .addFilterBefore(customAuthenticationFilter(http, authenticationManager),UsernamePasswordAuthenticationFilter.class);
                */
                /* AuthenticationProvider 추가 방법 2
                .authenticationProvider(new CustomAuthenticationProvider())
                .authenticationProvider(new CustomAuthenticationProvider2()); */
        /* AuthenticationManager
        http.authorizeHttpRequests(auth->auth
                        .requestMatchers("/", "/api/login").permitAll()
                        .anyRequest().authenticated())
                        .addFilterBefore(customAuthenticationFilter(http), UsernamePasswordAuthenticationFilter.class);
         */
                /* 요청 캐시
        // RequestCache를 통해서 세션으로부터 SavedRequest 정보 가져옴
        HttpSessionRequestCache requestCache=new HttpSessionRequestCache();
        // indexController
        requestCache.setMatchingRequestParameterName("customParam=y");

        // 요청 객체를 받아서 인증, 인가 설정
            // http 통신에 대한 인가 정책을 설정함을 의미
        http.authorizeHttpRequests(auth->auth
                        .requestMatchers("/logoutSuccess").permitAll()
                        .anyRequest().authenticated())
                .formLogin(form-> form
                        .successHandler(new AuthenticationSuccessHandler() {
                            @Override
                            public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                                // savedRequest 정보를 가져옴
                                SavedRequest savedRequest =requestCache.getRequest(request, response);
                                // 리다이렉트 할 url
                                String redirectUrl=savedRequest.getRedirectUrl();
                                response.sendRedirect(redirectUrl);
                            }
                        }))
                .requestCache(cache-> cache.requestCache(requestCache));
        // ExceptionTranslationFilter : 시큐리티에서 인증 인가에러 발생시 처리
         */
                /*
                                    // logout 성공시 연결되는 url에 인증 없이 접근 가능하게
                        .requestMatchers("/logoutSuccess").permitAll()
                        .anyRequest().authenticated())
                .formLogin(Customizer.withDefaults())
//                .csrf(csrf->csrf.disable()) // 로그아웃 get방식 사용 가능
                .logout(logout->logout
                                .logoutUrl("/logout") // 로그아웃 요청
                                .logoutRequestMatcher(new AntPathRequestMatcher("/logout","POST")) // 경로와 메소드 url보다 우선시됨
                                                                                // controller에 페이지가 없는 상태 -> 메소드를 get으로 바꾸거나 지움
                                .logoutSuccessUrl("/logoutSuccess") // 로그아웃 성공시 이동 -> controller에서 맵핑
                                .logoutSuccessHandler(new LogoutSuccessHandler() {
                                    @Override
                                    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                                        // 루트로 가거나 사용자 객체 정보 표시하거나 기능
                                        response.sendRedirect("/logoutSuccess");
                                    }
                                })
                                .deleteCookies("JSESSIONID", "remember-me") // 쿠키삭제
                                .invalidateHttpSession(true) // 로그아웃시 세션 무효화
                                .clearAuthentication(true) // 로그아웃시 인증 객체 삭제
                                .addLogoutHandler(new LogoutHandler() {
                                    @Override
                                    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
                                        HttpSession session=request.getSession();
                                        session.invalidate();
                                        SecurityContextHolder.getContextHolderStrategy().getContext().setAuthentication(null); // 기존 인증 객체 삭제
                                        SecurityContextHolder.getContextHolderStrategy().clearContext();
                                    }
                                })
                                .permitAll()
                                // FilterChainProxy 모든 필터들에 요청을 보내고 가지고 있는 여러 필터를 호출하면서 요청 처리

                        );
                 */
                /* 익명 객체

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
         */
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
        /* sessionManagement() */
        http.authorizeHttpRequests(auth-> auth
                    .requestMatchers("/invalidSessionUrl", "/expiredUrl").permitAll()
                    .anyRequest().authenticated())
            .formLogin(Customizer.withDefaults())
            // 세션 관리
            .sessionManagement(session->session
                    // 동시 세션 제어를 위해 필수
                    .invalidSessionUrl("/invalidSessionUrl")
                    .maximumSessions(1)
                    .maxSessionsPreventsLogin(false) // false 최신 세션만 남김 <-> true 초과하는 로그인 차단
                    .expiredUrl("/expiredUrl")
                    );
        return http.build();
        // SpringBootWebSecurityConfiguration로 지나가지 않음
        // ConditionalOnWebApplication 어노테이션 -> DefaultWebSecurityCondition의 SecurityFilterChain이 존재하지 않는다는 메소드가 성립 X
    }

    /* SecurityContextRepository SecurityContextHolderFilter */
    public CustomAuthenticationFilter customAuthenticationFilter(HttpSecurity http, AuthenticationManager authenticationManager){
        CustomAuthenticationFilter customAuthenticationFilter=new CustomAuthenticationFilter(http);
        customAuthenticationFilter.setAuthenticationManager(authenticationManager);
        return customAuthenticationFilter;
    }
    // 방법 1 : 커스텀 필터에서 매니저 설정 후 인증
    /*
    public CustomAuthenticationFilter customAuthenticationFilter(HttpSecurity http, AuthenticationManager authenticationManager){
        CustomAuthenticationFilter customAuthenticationFilter=new CustomAuthenticationFilter(http);
        customAuthenticationFilter.setAuthenticationManager(authenticationManager);
        return customAuthenticationFilter;
    }
     */
    // 방법 2 : 직접 ProviderManager를 만듦 -> 어떤 AuthenticationProvider를 사용할 지 리스트 객체를 생성자에 인자로 전달
    /*
    public CustomAuthenticationFilter customAuthenticationFilter(HttpSecurity http){
        List<AuthenticationProvider> list1=List.of(new DaoAuthenticationProvider());
        ProviderManager parent=new ProviderManager(list1);
        List<AuthenticationProvider> list2=List.of(new AnonymousAuthenticationProvider("key"), new CustomAuthenticationProvider());
        ProviderManager providerManager=new ProviderManager(list2,parent);

        CustomAuthenticationFilter customAuthenticationFilter=new CustomAuthenticationFilter(http);
        customAuthenticationFilter.setAuthenticationManager(providerManager);

        return customAuthenticationFilter;
    }
    */

    /* AuthenticationProvider Bean
    @Bean
    public AuthenticationProvider authenticationProvider(){
        return new CustomAuthenticationProvider();
    }
    @Bean
    public AuthenticationProvider authenticationProvider2(){
        return new CustomAuthenticationProvider2();
    }
    */

    /* Spring MVC */
    @Bean                                               // 설정클래스
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception{
        return configuration.getAuthenticationManager();
    }

    // 초기화시 작성되는 최초의 계정 작성 -> yaml과 겹쳤을 때에는 클래스가 우선
    @Bean // CustomUserDetailsService
    public UserDetailsService userDetailsService(){
        return new CustomUserDetailsService();
    /*
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
        return new InMemoryUserDetailsManager(user); // UserDetailsService 인터페이스를 상속
        */

    // http://localhost:8080/login?logout 로그인 된 계정 로그아웃 링크
    }
}
