package com.example.cors2;

import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.expression.DefaultHttpSecurityExpressionHandler;
import org.springframework.security.web.access.expression.WebExpressionAuthorizationManager;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.XorCsrfTokenRequestAttributeHandler;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RegexRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

@EnableWebSecurity
@Configuration
/* 메서드 기반 권한 부여(Secured, JSR250을 위해 true로) */
@EnableMethodSecurity(securedEnabled = true,jsr250Enabled = true)
public class SecurityConfig {
    /* 정적 자원 관리 <-> permitAll
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer(){
        // 자원 처리 무시.어떠한 자원 -> StaticResourceLocation에서 확인
        return web->web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }
    */

    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{
                                                // HttpSecurity.authorizeHttpRequest(), HttpSecurity.securityMatcher()
    public SecurityFilterChain securityFilterChain(HttpSecurity http, HandlerMappingIntrospector introspector) throws Exception{
                                                    // 표현식 및 커스텀 권한 구현
//    public SecurityFilterChain securityFilterChain(HttpSecurity http, ApplicationContext context)  throws Exception{
        /* CSRF
        http.authorizeHttpRequests(auth->auth
            .anyRequest().permitAll())
        .cors(cors->cors.configurationSource(corsConfigurationSource()));
        */
        /* CSRF 토큰 유지 및 검증
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
        */
        /* CSRF 통합
        // form
//        http.authorizeHttpRequests(auth->auth
//                    .requestMatchers("/csrf", "/csrfToken","/form", "/formCsrf").permitAll()
//                    .anyRequest().authenticated())
//                .formLogin(Customizer.withDefaults())
//                .csrf(Customizer.withDefaults());
        // cookie - JavaScript

        // 커스텀한 handler를 사용하기 때문에 설정
        SpaCsrfTokenRequestHandler csrfTokenRequestHandler=new SpaCsrfTokenRequestHandler();

        http.authorizeHttpRequests(auth->auth
                    .requestMatchers("/csrf","/csrfToken","/cookie","/cookieCsrf").permitAll()
                    .anyRequest().authenticated())
                .formLogin(Customizer.withDefaults())
                // 쿠키를 생성하는 repository + 자바스크립트에서 읽을 수 있게
                .csrf(csrf->csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                        .csrfTokenRequestHandler(csrfTokenRequestHandler))
                .addFilterBefore(new CsrfCookieFilter(), BasicAuthenticationFilter.class)
                // 쿠키의 유효성을 검증할 수 있는 클래스 -> SpaCsrfTokenRequestHandler
        // meta 태그는 실전 프로젝트에서
        ;
        */
        /* Same Site
        http.authorizeHttpRequests(auth->auth
                    .anyRequest().authenticated())
                .formLogin(Customizer.withDefaults());
        */
        /* HttpSecurity.authorizeHttpRequest()
        http.authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/","/login").permitAll() // 루트 경로는 누구나 접근 가능
                        .requestMatchers("/user").hasAuthority("ROLE_USER") // "/user" 엔드포인트에 대해 "USER" 권한을 요구합니다.
                        .requestMatchers("/myPage/**").hasRole("USER") // "/mypage" 및 하위 디렉터리에 대해 "USER" 권한을 요구합니다. Ant 패턴 사용.
                        .requestMatchers(HttpMethod.POST).hasAuthority("ROLE_WRITE") // POST 메소드를 사용하는 모든 요청에 대해 "write" 권한을 요구합니다.
                                        // requestMatchers 타입
                        .requestMatchers(new AntPathRequestMatcher("/manager/**")).hasAuthority("ROLE_MANAGER") // "/manager" 및 하위 디렉터리에 대해 "MANAGER" 권한을 요구합니다. AntPathRequestMatcher 사용.
                        // 아래 코드와 위치를 바꾸면 아래 설정 무시(manager가 admin/payment에 접근 가능)
                        .requestMatchers("/admin/**").hasAnyAuthority("ROLE_ADMIN", "ROLE_MANAGER") // "/admin" 및 하위 디렉터리에 대해 "ADMIN" 또는 "MANAGER" 권한 중 하나를 요구합니다.
                                                            // bean 주입 필요
                        .requestMatchers(new MvcRequestMatcher(introspector, "/admin/payment")).hasAuthority("ROLE_ADMIN") // "/manager" 및 하위 디렉터리에 대해 "MANAGER" 권한을 요구합니다. AntPathRequestMatcher 사용.
                        .requestMatchers(new RegexRequestMatcher("/resource/[A-Za-z0-9]+", null)).hasAuthority("ROLE_MANAGER") // 정규 표현식을 사용하여 "/resource/[A-Za-z0-9]+" 패턴에 "MANAGER" 권한을 요구합니다.
                        .anyRequest().authenticated())// 위에서 정의한 규칙 외의 모든 요청은 인증을 필요로 합니다.
                .formLogin(Customizer.withDefaults())
                .csrf(AbstractHttpConfigurer::disable); // POST 방식은 CSRF 토큰이 필요하기에 해제
        */
        /* 표현식 및 커스텀 권한 구현 - 스프링 시큐리티 기본 제공
        http.authorizeHttpRequests(authorize->authorize
                                                                                                        // isAnonymous() 등
                .requestMatchers("/user/{name}").access(new WebExpressionAuthorizationManager("#name==authentication.name")) // 값을 가져오기
                .requestMatchers("/admin/db").access(new WebExpressionAuthorizationManager("hasAuthority('ROLE_DB')or hasAuthority('ROLE_ADMIN')")) // 여러 개의 권한
                .anyRequest().authenticated())
            .formLogin(Customizer.withDefaults());
                */
        /* 표현식 및 커스텀 권한 구현 - 커스텀 표현식
        DefaultHttpSecurityExpressionHandler expressionHandler=new DefaultHttpSecurityExpressionHandler();
        expressionHandler.setApplicationContext(context);

                                                                                                    // 빈으로 만든 표현식 사용
        WebExpressionAuthorizationManager authorizationManager=new WebExpressionAuthorizationManager("@customWebSecurity.check(authentication, request)");
        authorizationManager.setExpressionHandler(expressionHandler);

        http.authorizeHttpRequests(authorize->authorize
                .requestMatchers("/custom/**").access(authorizationManager)
                .anyRequest().authenticated())
            .formLogin(Customizer.withDefaults());
        */
        /* 표현식 및 커스텀 권한 구현 - 커스텀 requestMatcher
        http.authorizeHttpRequests(authorize->authorize
                .requestMatchers(new CustomRequestMatcher("/admin")).hasAuthority("ROLE_ADMIN")
                .anyRequest().authenticated())
            .formLogin(Customizer.withDefaults());
        */
        /* HttpSecurity.securityMatcher() - 2개의 SecurityFilterChain Bean -> 모든 요청에 대해서 대응
        http.authorizeHttpRequests(authorize->authorize
                    .anyRequest().authenticated())
                .formLogin(Customizer.withDefaults());
         */
        /* 메서드 기반 권한 부여
        http.authorizeHttpRequests(authorize->authorize
                .anyRequest().authenticated())
            .formLogin(Customizer.withDefaults());
        */
        /* @PreFilter, @PostFilter
        http.authorizeHttpRequests(authorize->authorize
                .anyRequest().authenticated())
            .formLogin(Customizer.withDefaults())
            .csrf(AbstractHttpConfigurer::disable); // 꺼둠
        */
        /* @Secured, JSR-250 및 부가기능
        http.authorizeHttpRequests(authorize->authorize
                .anyRequest().permitAll())
            .formLogin(Customizer.withDefaults())
            .csrf(AbstractHttpConfigurer::disable);
        */
        /* 정적 자원 관리
        http.authorizeHttpRequests(authorize->authorize
                // permitAll
                .requestMatchers("/image").permitAll()
                .anyRequest().permitAll())
            .formLogin(Customizer.withDefaults())
            .csrf(AbstractHttpConfigurer::disable);
        */
        /* 계층적 권한 RoleHierarchy */
        http.authorizeHttpRequests(authorize->authorize
                .requestMatchers("/user").hasRole("USER")
                .requestMatchers("/db").hasRole("DB")
                .requestMatchers("/admin").hasRole("ADMIN")
                .anyRequest().authenticated())
            .formLogin(Customizer.withDefaults())
            .csrf(AbstractHttpConfigurer::disable);
        return http.build();
    }

    /* 계층적 권한 RoleHierarchy */
    @Bean
    public RoleHierarchy roleHierarchy(){
        RoleHierarchyImpl hierarchy=new RoleHierarchyImpl();
        // 초기화시 RoleHierarchy가 있는지 확인 Bean이 존재한다면 사용자의 권한을 확인해 해당 권한 하위권한까지 부여
        hierarchy.setHierarchy("ROLE_ADMIN > ROLE_DB\n" +
                                "ROLE_DB > ROLE_USER\n" +
                                "ROLE_USER > ROLE_ANONYMOUS");
                                // 띄어쓰기 필요
        return hierarchy;
    }

    /* HttpSecurity.securityMatcher() - 2개의 SecurityFilterChain Bean -> 특정 패턴에 대해서만 대응
    @Bean
    @Order(1) // 먼저 실행되도록 설정 -> 실행 순서가 뒤로 밀리면 적용 되지 않음(더 좁은 범위가 위로 가야함)
    public SecurityFilterChain securityFilterChain2(HttpSecurity http, HandlerMappingIntrospector introspector) throws Exception{
        http.securityMatchers(matchers->matchers.requestMatchers("/api/**", "/oauth/**"))
            .authorizeHttpRequests(authorize->authorize
                .anyRequest().permitAll());
        // 해당 특정한 패턴에 대해 설정해 다른 요청을 받지 않을 때 사용
        return http.build();
    }
    */

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
        UserDetails manager = User.withUsername("db").password("{noop}1111").roles("DB").build();
        UserDetails admin = User.withUsername("admin").password("{noop}1111").roles("ADMIN","SECURE").build();
        return  new InMemoryUserDetailsManager(user, manager, admin);
    }
}
