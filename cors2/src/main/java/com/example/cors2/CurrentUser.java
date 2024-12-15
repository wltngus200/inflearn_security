package com.example.cors2;

import org.springframework.security.core.annotation.AuthenticationPrincipal;

import java.lang.annotation.*;

/* Spring MVC 통합 */
@Target({ElementType.PARAMETER, ElementType.ANNOTATION_TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
@AuthenticationPrincipal
public @interface CurrentUser {

}
