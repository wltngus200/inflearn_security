package com.green.java.inflearnsecurity;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.CurrentSecurityContext;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class indexController {

    private final SessionInfoService sessionInfoService;
    @Autowired
    SecurityContextService securityContextService;

    // 서버 기동시 톰캣이 8080 포트로 가동
    // 요청 캐시
    /*
    @GetMapping("/")
    public String index(String customParam){
        if(customParam!=null){
            return "CustomParam";
        }
        return "index";
        // id: user pw: 콘솔창 랜덤 문자열 입력시 인증 됨
    }
    */
    /*
    // SecurityContext를 가지고 옴
    @GetMapping("/")
    public String index(){
                                                            // 이전에는 getContext 현재의 방법이 더 안전
                                        // 전역적으로 사용 가능
        SecurityContext securityContext=SecurityContextHolder.getContextHolderStrategy().getContext(); // 현재 인증 받은 정보가 담겨있음
        Authentication authentication=securityContext.getAuthentication();
        System.out.println("authentication"+authentication);

        securityContextService.securityContext();

        return "index";
    }
    */
    @GetMapping("/")
    public Authentication index(Authentication authentication){
        return authentication;
    }

    // 모든 요청에 대해 인증을 거쳐야 함 -> 인증이 안 된 사용자 form로그인 -> 우리가 커스텀한 로그인 페이지
    // 즉, SecurityConfig에서 form.loginPage()의 url값과 동일해야 함
    @GetMapping("/loginPage")
    public String loginPage(){
        // 뷰, HTML 렌더링 설정 X
        return "login page";
    }
    @GetMapping("/home")
    public String home(){
        return "login success";
    }

    // 익명 객체
    @GetMapping("/anonymous") // 익명 개체들이 접근 가능하게 설정되어있음
    public String anonymous(){
        return "anonymous";
    }
    @GetMapping("/authentication")
                                // 인증 받은 사용자의 인증객체 or 익명 사용자의 null
    public String authentication(Authentication authentication){
                        // 타입 확인
        if(authentication instanceof AnonymousAuthenticationToken){
            return "anonymous";
        }return "not anonymous";
    }
    // 어노테이션으로 접근 위의 방식으로는 익명객체를 참조할 수 없음
    @GetMapping("/anonymousContext")
    public String anonymousContext(@CurrentSecurityContext SecurityContext context){
        return context.getAuthentication().getName();
    }

    // 로그아웃하여 인증정보가 사라진 사용자가 접근 할 수 있는 페이지
    @GetMapping("/logoutSuccess")
    public String logoutSuccess(){
        return "logoutSuccess";
    }


    // sessionManagement()
    @GetMapping("/invalidSessionUrl")
    public String invalidSessionUrl(){
        return "logoutSuccess";
    }

    @GetMapping("/expiredUrl")
    public String expiredUrl(){
        return "expiredUrl";
    }

    /* SessionManagementFilter/ConcurrentSessionFilter
    @GetMapping("/sessionInfo")
    public String sessionInfo(){
        sessionInfoService.sessionInfo();
        return "sessionInfo";
    }
    */

    @GetMapping("/login")
    public String login(){
        return "loginPage";
    }

    @GetMapping("/denied")
    public String denied(){
        return "denied";
    }
}
