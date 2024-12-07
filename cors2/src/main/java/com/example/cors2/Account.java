package com.example.cors2;


import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class Account {
    private String owner;
    private boolean isSecure;
}