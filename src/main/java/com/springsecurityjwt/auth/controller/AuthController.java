package com.springsecurityjwt.auth.controller;

import com.springsecurityjwt.auth.dto.SigninRequest;
import com.springsecurityjwt.auth.dto.SigninResponse;
import com.springsecurityjwt.auth.dto.SignupRequest;
import com.springsecurityjwt.auth.dto.SignupResponse;
import com.springsecurityjwt.auth.service.AuthService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@Tag(name = "User-Auth", description = "회원가입 로그인 API")
public class AuthController {

    private final AuthService authService;

    @PostMapping("/auth/signup")
    @Operation(summary = "회원가입")
    public SignupResponse signup(@Valid @RequestBody SignupRequest signupRequest) {
        return authService.signup(signupRequest);
    }

    @PostMapping("/auth/signin")
    @Operation(summary = "로그인")
    public SigninResponse signin(@Valid @RequestBody SigninRequest signinRequest) {
        return authService.signin(signinRequest);
    }
}