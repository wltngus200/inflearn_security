package com.example.cors2;

import org.springframework.security.access.prepost.PreAuthorize;

import java.lang.annotation.*;

// 어노테이션 RolesAllowed 복사
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE, ElementType.METHOD})
// 추가
@PreAuthorize("hasRole('ADMIN')")
public @interface IsAdmin {
}
