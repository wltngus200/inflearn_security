package com.example.cors2;

import org.springframework.security.core.annotation.AuthenticationPrincipal;

import java.lang.annotation.*;

/* Spring MVC 통합 */
@Target({ElementType.PARAMETER, ElementType.ANNOTATION_TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
                        // 표현식 (인증 받지 못 한 사용자는 anonymousUser 문자열로 Principle에 저장 -> username 필드 X)
@AuthenticationPrincipal(expression = "#this=='anonymousUser'?null:username")
                        // this는 principle을 의미
public @interface CurrentUsername {

}
