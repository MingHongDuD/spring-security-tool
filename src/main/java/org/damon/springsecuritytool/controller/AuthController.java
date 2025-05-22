package org.damon.springsecuritytool.controller;

import org.damon.springsecuritytool.auth.JwtTokenProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author damon 20250521
 */
@RestController
public class AuthController {

//    @Autowired
//    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtTokenProvider jwtTokenProvider;


    // 登录接口，接收用户名和密码，返回 JWT
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest loginRequest) {
        // 创建认证请求
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword());

        // 认证用户
//        Authentication authentication = authenticationManager.authenticate(authenticationToken);

//        // 生成 JWT
//        String jwt = jwtTokenProvider.createToken((JwtUserInfo) authentication.getPrincipal());
//
//        return ResponseEntity.ok(new JwtResponse(jwt));
    }
}

// 登录请求 DTO
class LoginRequest {
    private String username;
    private String password;

    // Getters and Setters
    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}

// JWT 响应 DTO
class JwtResponse {
    private String token;

    public JwtResponse(String token) {
        this.token = token;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }
}