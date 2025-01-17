package com.springsecurityjwt.auth.service;

import com.springsecurityjwt.auth.dto.SigninRequest;
import com.springsecurityjwt.auth.dto.SigninResponse;
import com.springsecurityjwt.auth.dto.SignupRequest;
import com.springsecurityjwt.auth.dto.SignupResponse;
import com.springsecurityjwt.config.JwtUtil;
import com.springsecurityjwt.config.PasswordEncoder;
import com.springsecurityjwt.user.entity.User;
import com.springsecurityjwt.user.enums.UserRole;
import com.springsecurityjwt.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;

    @Transactional
    public SignupResponse signup(SignupRequest signupRequest) {

        if (userRepository.existsByUsername(signupRequest.getUsername())) {
            throw new IllegalArgumentException("Username is already in use");
        }

        String encodedPassword = passwordEncoder.encode(signupRequest.getPassword());

        UserRole userRole = UserRole.USER;

        User user = new User(signupRequest.getUsername(), signupRequest.getNickname(), encodedPassword, userRole);

        userRepository.save(user);

        return new SignupResponse(user.getUsername(), user.getNickname(), List.of(SignupResponse.Authority.fromUserRole(user.getUserRole())));
    }

    @Transactional
    public SigninResponse signin(SigninRequest signinRequest) {

        User user = userRepository.findByUsername(signinRequest.getUsername())
                .orElseThrow(() -> new IllegalArgumentException("Username not found"));

        if (!passwordEncoder.matches(signinRequest.getPassword(), user.getPassword())) {
            throw new IllegalArgumentException("Wrong password");
        }

        String token = jwtUtil.createToken(user.getId(), user.getNickname(), user.getNickname(), user.getUserRole());

        return new SigninResponse(token);
    }
}
