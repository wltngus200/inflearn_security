package com.example.cors2.method;


import org.aopalliance.intercept.MethodInvocation;
import org.springframework.aop.Advisor;
import org.springframework.aop.Pointcut;
import org.springframework.aop.aspectj.AspectJExpressionPointcut;
import org.springframework.aop.support.ComposablePointcut;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Role;
import org.springframework.security.authorization.AuthorityAuthorizationManager;
import org.springframework.security.authorization.method.AuthorizationManagerAfterMethodInterceptor;
import org.springframework.security.authorization.method.AuthorizationManagerBeforeMethodInterceptor;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;



@EnableMethodSecurity(prePostEnabled = false) // 우리가 만든 클래스만 처리
@Configuration
public class MethodSecurityConfig {
    /* Custom AuthorizationManager
    @Bean
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    public Advisor preAuthorize(){
        return AuthorizationManagerBeforeMethodInterceptor.preAuthorize(new MyPreAuthorizationManager());
    }

    @Bean
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    public Advisor postAuthorize(){
        return AuthorizationManagerAfterMethodInterceptor.postAuthorize(new MyPostAuthorizationManager());
    }
    */
    /* 포인트 컷 메서드 보안 구현 */
    // 단일 포인트 컷
//    @Bean
//    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
//    public Advisor pointCutAdvisor(){
//        // 포인트 컷 객체
//        AspectJExpressionPointcut pattern=new AspectJExpressionPointcut();
//        pattern.setExpression("execution(* com.example.cors2.DataService.getUser(..))");
//
//        // 매니저 필요
//        AuthorityAuthorizationManager<MethodInvocation> manager=AuthorityAuthorizationManager.hasRole("USER");
//
//        // 메소드 진입 전 권한 검사
//        return new AuthorizationManagerBeforeMethodInterceptor(pattern, manager);
//    }
    // 다중 포인트 컷
    @Bean
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    public Advisor pointCutAdvisor(){
        AspectJExpressionPointcut pattern1=new AspectJExpressionPointcut();
        pattern1.setExpression("execution(* com.example.cors2.DataService.getUser(..))");

        AspectJExpressionPointcut pattern2=new AspectJExpressionPointcut();
        pattern2.setExpression("execution(* com.example.cors2.DataService.getOwner(..))");

        ComposablePointcut composablePointcut=new ComposablePointcut((Pointcut) pattern1);
        composablePointcut.union((Pointcut)pattern2);

        AuthorityAuthorizationManager<MethodInvocation> manager=AuthorityAuthorizationManager.hasRole("USER");

        return new AuthorizationManagerBeforeMethodInterceptor(composablePointcut, manager);
    }

}
