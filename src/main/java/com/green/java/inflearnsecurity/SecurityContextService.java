package com.green.java.inflearnsecurity;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

@Service
public class SecurityContextService {
    public void securityContext(){
                                        // 전역적으로 사용 가능하기에 별도의 동작이 필요 X
        SecurityContext securityContext= SecurityContextHolder.getContextHolderStrategy().getContext(); // 현재 인증 받은 정보가 담겨있음
        Authentication authentication=securityContext.getAuthentication();
        System.out.println("authentication"+authentication);
    }
}
