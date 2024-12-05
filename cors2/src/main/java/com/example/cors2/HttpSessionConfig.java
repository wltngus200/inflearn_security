package com.example.cors2;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.session.MapSession;
import org.springframework.session.MapSessionRepository;
import org.springframework.session.SessionRepository;
import org.springframework.session.config.annotation.web.http.EnableSpringHttpSession;
import org.springframework.session.web.http.CookieSerializer;
import org.springframework.session.web.http.DefaultCookieSerializer;

import java.util.concurrent.ConcurrentHashMap;

// Same site
@Configuration // Bean
@EnableSpringHttpSession // 의존성 추가 필요
public class HttpSessionConfig {
    @Bean
    public CookieSerializer cookieSerializer(){
        DefaultCookieSerializer serializer=new DefaultCookieSerializer();
        serializer.setUseHttpOnlyCookie(true); // Http 통신에만 사용
        serializer.setUseSecureCookie(true); // 보안 쿠키
        serializer.setSameSite("Lax");
        // None : 크로스 사이트간 쿠키 전송 허용 -> HTTPS, 보안쿠키 사용
        // Strict : 가장 엄격
        return serializer;
    }

    @Bean
    public SessionRepository<MapSession> sessionRepository(){
        return new MapSessionRepository(new ConcurrentHashMap<>());
    }
}
