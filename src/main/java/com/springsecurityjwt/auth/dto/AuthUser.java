package com.springsecurityjwt.auth.dto;

import com.springsecurityjwt.user.enums.UserRole;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collection;
import java.util.Collections;

@Getter
public class AuthUser {

    private final Long id;
    private final String username;
    private final String nickname;
    private final UserRole role;

    public AuthUser(Long id, String username, String nickname, UserRole role) {
        this.id = id;
        this.username = username;
        this.nickname = nickname;
        this.role = role;
    }

    public Collection<GrantedAuthority> getAuthorities() {
        return Collections.singletonList(new SimpleGrantedAuthority(role.getAuthority()));
    }
}
