package com.example.cors2;

import org.springframework.scheduling.annotation.Async;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

/* Spring MVC 비동기 통합 */
@Service
public class AsyncService {
    // 비동기 실행을 하도록 스프링이 설치
    @Async
    // Async 어노테이션 작동을 위해 어플리케이션에 어노테이션 추가
    public void asyncMethod(){
        SecurityContext securityContext= SecurityContextHolder.getContextHolderStrategy().getContext();
        System.out.println("securityContext : " + securityContext);
        System.out.println("Child Thread : " + Thread.currentThread().getName());
    }
}
