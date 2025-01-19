package com.springsecurityjwt.config;

import com.springsecurityjwt.user.enums.UserRole;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.security.Key;
import java.util.Base64;
import java.util.Date;

@Slf4j(topic = "JwtUtil")
@Component
public class JwtUtil {

    private static final String BEARER_PREFIX = "Bearer ";
    private static final long TOKEN_TIME = 60 * 60 * 1000L;

    @Value("${jwt.secret.key}")
    private String secretKey;

    private Key key;
    private static final SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;

    @PostConstruct
    public void init() {
        byte[] bytes = Base64.getDecoder().decode(secretKey);
        key = Keys.hmacShaKeyFor(bytes);
    }

    public String createToken(Long userId, String nsername, String nickname, UserRole userRole) {
        Date date = new Date();

        return BEARER_PREFIX
                + Jwts.builder()
                .setSubject(String.valueOf(userId))
                .claim("username", nsername)
                .claim("nickname", nickname)
                .claim("userRole", userRole)
                .setExpiration(new Date(date.getTime() + TOKEN_TIME))
                .setIssuedAt(date) // 발급일
                .signWith(key, signatureAlgorithm) // 암호화 알고리즘
                .compact();
    }

    public String substringToken(String tokenValue) {
        if (StringUtils.hasText(tokenValue) && tokenValue.startsWith(BEARER_PREFIX)) {
            return tokenValue;
        }
        throw new IllegalArgumentException("Token is missing or invalid");
    }

    public Claims extractClaims(String token) {
        return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody();
    }

    public String createRefreshToken(Long userId) {
        Date now = new Date();
        long refreshTokenValidity = 7 * 24 * 60 * 60 * 1000L; // 7일

        return Jwts.builder()
                .setSubject(String.valueOf(userId))
                .setExpiration(new Date(now.getTime() + refreshTokenValidity))
                .setIssuedAt(now)
                .signWith(key, signatureAlgorithm)
                .compact();
    }
}