package com.example.cors2;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class ViewController {
    @GetMapping("/form")
    public String form(){
        return "form";
    }
    // 쿠키를 볼 수 있는 페이지
    @GetMapping("/cookie")
    public String cookie(){
        // cookie.html의 버튼
        return "cookie";
    }
}