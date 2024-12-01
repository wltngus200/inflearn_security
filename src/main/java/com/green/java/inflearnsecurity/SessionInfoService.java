package com.green.java.inflearnsecurity;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class SessionInfoService {
    private final SessionRegistry sessionRegistry;
    public void sessionInfo(){
        // 모든 사용자 정보, 세션을 가져와 세션 아이디를 통해 정보를 출력
        for(Object principal : sessionRegistry.getAllPrincipals()){
            List<SessionInformation> allSessions=
                                                        // 만료된 세션 포함 여부
            sessionRegistry.getAllSessions(principal, false);
            for(SessionInformation sessionInformation : allSessions){
                System.out.println("사용자 : "+ principal
                        +"세션ID : "+sessionInformation.getSessionId()
                        +"세션 시간 : "+sessionInformation.getLastRequest());
            }
        }

    }
}
