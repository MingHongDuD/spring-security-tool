package org.damon.springsecuritytool;

import org.damon.springsecuritytool.auth.JwtTokenProvider;
import org.damon.springsecuritytool.dto.auth.JwtUserInfo;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class SpringSecurityToolApplicationTests {

    private JwtTokenProvider jwtTokenProvider;

    @Test
    void contextLoads() {
    }

    @Test
    void generaToken() {
        JwtUserInfo jwtUserInfo = new JwtUserInfo();
        jwtUserInfo.setUserId("1");
        jwtUserInfo.setCity("大连");
        jwtUserInfo.setUsername("user");
        String token = jwtTokenProvider.createToken(jwtUserInfo);
        System.out.println(token);
    }

}
