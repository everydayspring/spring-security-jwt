package com.springsecurityjwt.auth.service;

import com.springsecurityjwt.auth.dto.*;
import com.springsecurityjwt.auth.entity.RefreshToken;
import com.springsecurityjwt.auth.repository.RefreshTokenRepository;
import com.springsecurityjwt.config.JwtUtil;
import com.springsecurityjwt.config.PasswordEncoder;
import com.springsecurityjwt.user.entity.User;
import com.springsecurityjwt.user.enums.UserRole;
import com.springsecurityjwt.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class AuthService {

    private final RefreshTokenRepository refreshTokenRepository;
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

        String accessToken = jwtUtil.createToken(user.getId(), user.getUsername(), user.getNickname(), user.getUserRole());
        String refreshToken = jwtUtil.createRefreshToken(user.getId());

        refreshTokenRepository.deleteByUserId(user.getId());
        refreshTokenRepository.flush();
        refreshTokenRepository.save(new RefreshToken(user.getId(), refreshToken, LocalDateTime.now().plusDays(7)));

        return new SigninResponse(accessToken, refreshToken);
    }

    @Transactional
    public RefreshTokenResponse reissueAccessToken(RefreshTokenRequest refreshTokenRequest) {
        RefreshToken tokenEntity = refreshTokenRepository.findByToken(refreshTokenRequest.getRefreshToken())
                .orElseThrow(() -> new IllegalArgumentException("Invalid refresh token"));

        if (tokenEntity.getExpirationDate().isBefore(LocalDateTime.now())) {
            throw new IllegalArgumentException("Refresh token has expired");
        }

        User user = userRepository.findById(tokenEntity.getUserId())
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        String newToken = jwtUtil.createToken(user.getId(), user.getUsername(), user.getNickname(), user.getUserRole());

        return new RefreshTokenResponse(newToken);
    }
}
