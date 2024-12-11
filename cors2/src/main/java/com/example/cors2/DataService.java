package com.example.cors2;

import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PostFilter;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.access.prepost.PreFilter;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/* @PreFilter, @PostFilter -> SecurityConfig의 @EnableMethodSecurity */
@Service
public class DataService {
    /*
    // 인증 받은 사용자의 name과 Filter가 가진 List에 있는 owner와 동일할 경우
    @PreFilter("filterObject.owner==authentication.name")
    public List<Account> writeList(List<Account> data){
        return data;
    }

                            // Map은 value로 접근
    @PreFilter("filterObject.value.owner==authentication.name")
    public Map<String, Account> writeMap(Map<String, Account> data){
        return data;
    }

    @PostFilter("filterObject.owner==authentication.name")
    public List<Account> readList(){
        return new ArrayList<>(List.of(
                new Account("user", false),
                new Account("db", false),
                new Account("admin", false)
        ));
    }

    @PostFilter("filterObject.value.owner==authentication.name")
    public Map<String, Account> readMap(){
        return new HashMap<>(Map.of(
                "user", new Account("user", false),
                "db", new Account("db", false),
                "admin", new Account("admin", false)
        ));
    }
    */
    /* 메서드 기반 인가 관리자 */
    @PreAuthorize("hasAuthority('ROLE_USER')")
    public String getUser(){
        return "user";
    }

    @PostAuthorize("returnObject.owner==authentication.name")
    public Account getOwner(String name){
        return new Account(name, false);
    }

    public String display(){
        return "display";
    }
}
