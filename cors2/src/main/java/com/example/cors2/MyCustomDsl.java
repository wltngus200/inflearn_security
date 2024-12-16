package com.example.cors2;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter;

/* Custom DSLs */
public class MyCustomDsl extends AbstractHttpConfigurer<MyCustomDsl, HttpSecurity> {
    private boolean flag;

    public boolean setFlag(boolean value){ // setter
        return flag=value;
    }

    @Override
    public void init(HttpSecurity http) throws Exception {
        super.init(http);
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        // 필터를 만듦
        MyCustomFilter myCustomFilter=new MyCustomFilter();
        myCustomFilter.setFlag(flag); // Dsl에서 설정한 값
        // 래퍼 클래스 뒤에 필터가 오도록 추가(서블릿에서도 인증을 받을 수 있게 통합)
        http.addFilterAfter(myCustomFilter, SecurityContextHolderAwareRequestFilter.class);
                                            // 이 필터에서 작업을 한 리퀘스트 객체가 넘어가야 함
    }

    public static MyCustomDsl customDsl(){
        return new MyCustomDsl();
    }

//    public MyCustomDsl flag(boolean value) {
//        this.flag = value;
//        return this;
//    }
}
