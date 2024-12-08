package com.example.cors2;

import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;

import java.lang.annotation.*;

// 어노테이션 RolesAllowed 복사
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE, ElementType.METHOD})
// 추가
@PostAuthorize("returnObject.owner==authentication.name")
public @interface OwnerShip {
}
