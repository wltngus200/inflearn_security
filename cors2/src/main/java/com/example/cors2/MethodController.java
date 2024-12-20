package com.example.cors2;

import jakarta.annotation.security.DenyAll;
import jakarta.annotation.security.PermitAll;
import jakarta.annotation.security.RolesAllowed;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequiredArgsConstructor
public class MethodController {

    private final DataService dataService;

    /* @PreAuthorize, @PostAuthorize
    @GetMapping("/admin")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public String admin(){
        return "admin";
    }

    @GetMapping("/user")
    @PreAuthorize("hasAnyAuthority('ROLE_ADMIN','ROLE_USER')")
    public String user(){
        return "user";
    }

    @GetMapping("/isAuthenticated")
    @PreAuthorize("isAuthenticated")
    public String isAuthenticated(){
        return "isAuthenticated";
    }

    @GetMapping("/user/{id}")
    @PreAuthorize("#id==authentication.name") // # 빼먹지 말기
    public String authentication(@PathVariable(name="id") String id){
        return id;
    }

    // PostAuthorize
    @GetMapping("/owner")
    @PostAuthorize("returnObject.owner==authentication.name")
    public Account owner(String name){
        return new Account(name, false);
    }

    @GetMapping("/isSecure")
    @PostAuthorize("hasAuthority('ROLE_ADMIN') and returnObject.isSecure")
    public Account isSecure(String name, String secure){
        return new Account(name, "Y".equals(secure));
    }
    */

    /* @PreFilter, @PostFilter
    @PostMapping("/writeList")
                                    // JSON 형식의 User 객체 3개
    public List<Account> writeList(@RequestBody List<Account> data){
        return dataService.writeList(data);
    }

    @PostMapping("/writeMap")
    public Map<String, Account> writeMap(@RequestBody List<Account> data){
        // List를 Map로 변경                // Key를 지정, Value를 지정
        Map<String, Account> accountMap=data.stream().collect(Collectors.toMap(account->account.getOwner(),account->account));
        return dataService.writeMap(accountMap);
    }

    // PostFilter
    @GetMapping("/readList")
    public List<Account> readList(){
        return dataService.readList();
    }

    @GetMapping("/readMap")
    public Map<String, Account> readMap(){
        return dataService.readMap();
    }*/

    /* @Secured, JSR-250 및 부가기능
    @GetMapping("/user")
    @Secured("ROLE_USER")
    public String user(){
        return "user";
    }*/

//    @GetMapping("/admin")
//    @RolesAllowed("ADMIN")
//    public String admin(){
//        return "admin";
//    }

    @GetMapping("/permitAll") // 요청 기반 권한
    @PermitAll // 메소드 수준 권한 -> anyRequest().permitAll()이어야 접근 가능
    public String permitAll(){
        return "permitAll";
    }

    @GetMapping("/denyAll")
    @DenyAll
    public String denyAll(){
        return "denyAll ";
    }

    @GetMapping("/isAdmin")
    @IsAdmin
    public String isAdmin(){
        return "isAdmin";
    }

    @GetMapping("/ownerShip")
    @OwnerShip
    public Account ownerShip(String name){
        return new Account(name, false);
    }

    @GetMapping("/delete")
                    // 빈 이름. 메소드(객체 타입)
    @PreAuthorize("@myAuthorizer.isUser(#root)")
    public String delete(String name){
        return "delete";
    }

}
