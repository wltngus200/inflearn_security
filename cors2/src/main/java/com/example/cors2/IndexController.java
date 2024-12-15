package com.example.cors2;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.Callable;


@RestController
//@RequestMapping("/api")
@RequiredArgsConstructor
public class IndexController {
    /*private final DataService dataService;

    public IndexController(DataService dataService) {
        this.dataService = dataService;
    }*/
//    @GetMapping("/")
//    public Authentication index(Authentication authentication){
//        return authentication;
//    }

//    @GetMapping("/users")
//    public String users(){
//        // Json 형식
//        return "{\"name\": \"hong gil-dong\"}";
//    }
    // 서블릿 MVC에서 토큰을 가져와 사용
    // 필터가 세션에 저장하기 전에 지연된 객체를 request 객체에 저장(토큰 이름, 문자열)
    @GetMapping("/csrfToken")
    public String csrfToken(HttpServletRequest request){
        // 실제 토큰이 아닌 진짜 토큰을 가진 객체를 실행시키기 위한 지연된 객체
        CsrfToken csrfToken1=(CsrfToken)request.getAttribute(CsrfToken.class.getName());
        CsrfToken csrfToken2=(CsrfToken)request.getAttribute("_csrf");

        // supplier를 호출해 세션으로부터 객체를 가져오거나 새로 생성하고 토큰값 리턴
        String token=csrfToken1.getToken();
        return token;
    }

    @PostMapping("/csrf")
    public String csrf(){
        return "csrf 적용";
    }

    /* CSRF 통합 */
    @PostMapping("/formCsrf")
    public CsrfToken formCsrf(CsrfToken csrfToken){
                            // 자동적으로 현재 생성된 CSRF 토큰 객체 반영
        return csrfToken;
    }

    // cookie.html의 메소드
    @PostMapping("/cookieCsrf")
    public CsrfToken cookieCsrf(CsrfToken csrfToken){
                            // 자동적으로 현재 생성된 CSRF 토큰 객체 반영
        return csrfToken;
    }

    // authorizeHttpRequests
//    @GetMapping("/user")
//    public String user(){
//        return "user";
//    } MethodController

    @GetMapping("/myPage/points")
    public String myPage(){
        return "myPage";
    }

    @GetMapping("/manager")
    public String manager(){
        return "manager";
    }

    @GetMapping("/admin")
    public String admin(){
        return "admin";
    }

    @GetMapping("/admin/payment")
    public String adminPayment(){
        return "adminPayment";
    }

    @GetMapping("/resource/address_01") // 정규표현식에 해당 X(특수 문자)
    public String address_01(){
        return "address_01";
    }

    @GetMapping("/resource/address01")
    public String address01(){
        return "address01";
    }

    @PostMapping("/post")
    public String post(){
        return "post";
    }

    /* 표현식 및 커스텀 권한 구현 - 중복 제외 */
//    @GetMapping("/user/{name}")
//    public String userName(@PathVariable String name){
//        return name;
//    } MethodController

    @GetMapping("/admin/db")
    public String admindb(){
        return "admin";
    }

//    @GetMapping("/")
//    public String index(HttpServletRequest request){
//        return "index";
//    }

    @GetMapping("/custom") // 커스텀 표현식
    public String custom(){
        return "custom";
    }

    /* HttpSecurity.securityMatcher()
    @GetMapping("/api/photos")
    public String photos(){
        return "photos";
    }

    @GetMapping("/oauth/login")
    public String oauth(){
        return "oauthLogin";
    }

    @GetMapping("/db")
    public String db(){
        return "db";
    }

    @GetMapping("/secure")
    public String secure(){
        return "secure";
    }
    */
    /* 메서드 기반 인가 관리자
    @GetMapping("/user")
    public String user(){
        return dataService.getUser();
    }

    @GetMapping("/owner")
    public Account owner(String name){
        return dataService.getOwner(name);
    }
    @GetMapping("/display")
    public String display(){
        return dataService.display();
    }
    */
    /* Servlet API 통합
    @GetMapping("/login")
    public String login(HttpServletRequest request, MemberDto memberDto) throws ServletException {
        request.login(memberDto.getUsername(), memberDto.getPassword());
        System.out.println("login is successful");
        return "login";
    }

    @GetMapping("/users")
    public List<MemberDto> users(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        boolean authenticate=request.authenticate(response);
        if(authenticate){
            return List.of(new MemberDto("user", "1111"));
        }
        return Collections.emptyList();
    }
    */
    /* Spring MVC 통합 */

    // 인증객체가 익명상태일 경우
    AuthenticationTrustResolverImpl trustResolver=new AuthenticationTrustResolverImpl();

    @GetMapping("/")
    // 스프링 시큐리티에서 인증 객체 가져오기
    public String index(){
        Authentication authentication=SecurityContextHolder.getContextHolderStrategy().getContext().getAuthentication();
        // 익명 사용자 구분
        return trustResolver.isAnonymous(authentication)?"Anonymous":"authenticated";
    }
    // 어노테이션을 통해 인증 객체 가져오기
    @GetMapping("/user")
    public User user(@AuthenticationPrincipal User user){ // User=스프링 시큐리티 제공
        return user; // principle를 가져옴
    }
    // 표현식을 통해 인증 객체 가져오기
    @GetMapping("/username")                    // User 안의 멤버필드 이름(없는 것을 지정할 경우 500에러)
    public String username(@AuthenticationPrincipal(expression="username") String username){
                            // AuthenticationPrincipalArgumentResolver에서 처리
        return username;
    }
    // 메타 주석 -> 클래스
    @GetMapping("/currentUser")
    public User currentUser(@CurrentUser User user){
        return user;
    }

    @GetMapping("/currentUsername")
    public String currentUsername(@CurrentUsername String username){
        return username;
    }

    /* Spring MVC 비동기 통합 */

    // 컨트롤러에서 Callable 타입 반환 -> 비동기 스레드 생성되어 실행(부모 자식 간의 SecurityContext가 공유되는지)
    @GetMapping("callable") // callable 실행은 callable 타입 반환
    public Callable<Authentication> call(){ // 실행 : 부모스레드(Tomcat에서 만듦)
        SecurityContext securityContext=SecurityContextHolder.getContextHolderStrategy().getContext();
        System.out.println("securityContext : " + securityContext);
        System.out.println("Parent Thread : " + Thread.currentThread().getName());

        // callable 실행
        return new Callable<Authentication>(){ // 자식 스레드
            @Override
            public Authentication call() throws Exception{
                SecurityContext securityContext=SecurityContextHolder.getContextHolderStrategy().getContext();
                System.out.println("securityContext : " + securityContext);
                System.out.println("Child Thread : " + Thread.currentThread().getName());
                return securityContext.getAuthentication();
            }
        };
    }

    private final AsyncService asyncservice;

    // 다른 비동기 기술
    @GetMapping("/async")
    public Authentication async(){ // 부모 스레드(WAS에서 실행) 실행 -> AsyncService
        SecurityContext securityContext=SecurityContextHolder.getContextHolderStrategy().getContext();
        System.out.println("securityContext : " + securityContext);
        System.out.println("Parent Thread : " + Thread.currentThread().getName());

        // Async 어노테이션 작동을 위해 어플리케이션에 어노테이션 추가
        asyncservice.asyncMethod(); // 자식 스레드 실행 -> 부모가 가진 SecurityContext 공유 X
        // 상속 가능한 ThreadLocal 모드 설정 시 Async도 공유되게 됨
        return securityContext.getAuthentication();
    }
}
