package com.example.cors2;


import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@AllArgsConstructor
/* @PreFilter, @PostFilter */
@Setter
@NoArgsConstructor
public class Account {
    private String owner;
    private boolean isSecure;
}