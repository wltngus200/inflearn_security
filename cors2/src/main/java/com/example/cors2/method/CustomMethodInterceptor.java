package com.example.cors2.method;

import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.nio.file.AccessDeniedException;

/* AOP 메서드 보안 */                                // aopalliance
public class CustomMethodInterceptor implements MethodInterceptor {
    // 권한 심사를 수행하게 할 AuthorizationManger
    private final AuthorizationManager<MethodInvocation> authorizationManger;

    public CustomMethodInterceptor(AuthorizationManager<MethodInvocation> authorizationManger){
        this.authorizationManger=authorizationManger;
    }

    @Override
    public Object invoke(MethodInvocation invocation) throws Throwable {
        Authentication authentication=SecurityContextHolder.getContextHolderStrategy().getContext().getAuthentication();
        // 권한 심사는 authorizationManger가 판단 성공 여부만 확인
                            // check의 파라미터는 서플라이어(인증객체)+오브젝트
        if(authorizationManger.check(()->authentication, invocation).isGranted()){
            // 성공하였을 때 실제 메소드 호출
            return invocation.proceed();
        }
        throw new AccessDeniedException("Access Denied");
    }
}
