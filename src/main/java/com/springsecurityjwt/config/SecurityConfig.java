package com.springsecurityjwt.config;

import com.springsecurityjwt.user.enums.UserRole;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter;

@Configuration
@RequiredArgsConstructor
@EnableWebSecurity
@EnableMethodSecurity(securedEnabled = true)
public class SecurityConfig {

    private final JwtSecurityFilter jwtSecurityFilter;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http.csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(
                        session ->
                                session.sessionCreationPolicy(
                                        SessionCreationPolicy.STATELESS) // SessionManagementFilter,
                        // SecurityContextPersistenceFilter
                )
                .addFilterBefore(jwtSecurityFilter, SecurityContextHolderAwareRequestFilter.class)
                // UsernamePasswordAuthenticationFilter 및 DefaultLoginPageGeneratingFilter 비활성화
                .formLogin(AbstractHttpConfigurer::disable)
                // AnonymousAuthenticationFilter 비활성화 (익명 사용자 허용 X)
                .anonymous(AbstractHttpConfigurer::disable)
                // BasicAuthenticationFilter 비활성화 (HTTP Basic 인증 비활성화)
                .httpBasic(AbstractHttpConfigurer::disable)
                // LogoutFilter 비활성화 (로그아웃 기능 비활성화)
                .logout(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(
                        auth ->
                                auth.requestMatchers("/auth/signin", "/auth/signup")
                                        .permitAll()
                                        .requestMatchers("/test")
                                        .hasAuthority(UserRole.ADMIN.getAuthority())
                                        .anyRequest()
                                        .authenticated())
                .build();
    }
}
