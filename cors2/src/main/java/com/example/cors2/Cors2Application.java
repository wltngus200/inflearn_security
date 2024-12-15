package com.example.cors2;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableAsync;

@SpringBootApplication
@EnableAsync // Async 어노테이션을 위한 설정
public class Cors2Application {

	public static void main(String[] args) {
		SpringApplication.run(Cors2Application.class, args);
	}

}
