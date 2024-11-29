package com.green.java.inflearnsecurity;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class LoginController {
    private final AuthenticationManager authenticationManager; // 빈 등록 필요 -> SecurityConfig
    private final HttpSessionSecurityContextRepository securityContextRepository=new HttpSessionSecurityContextRepository();

    @PostMapping("/login")
    public Authentication login(@RequestBody LoginRequest login, HttpServletRequest request, HttpServletResponse response){
        // 사용자가 입력한 아이디 패스워드를 토큰에 저장
        UsernamePasswordAuthenticationToken token=
                                                            // 인증 받기 전은 권한 줄 필요 X 인증 후
                // 새 객체 생성 new UsernamePasswordAuthenticationToken(login.getUsername(),login.getPassword());
                UsernamePasswordAuthenticationToken.unauthenticated(login.getUsername(), login.getPassword()); // 메소드 활용
        // 유저가 입력한 정보를 전달해 인증 수행하고 인증 객체 반환
        Authentication authentication=authenticationManager.authenticate(token);
        // 새로운 SecurityContext 객체를 만들어 반환된 인증 객체를 저장
        SecurityContext securityContext=SecurityContextHolder.getContextHolderStrategy().createEmptyContext();
        securityContext.setAuthentication(authentication);
        // SecuirtyContext를 ThreadLocal에 저장
        SecurityContextHolder.getContextHolderStrategy().setContext(securityContext);
        // 인증상태의 영속성
        securityContextRepository.saveContext(securityContext, request, response);

        return authentication;
    }

}
