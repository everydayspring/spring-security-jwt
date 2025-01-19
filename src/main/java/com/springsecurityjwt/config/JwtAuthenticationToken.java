package com.springsecurityjwt.config;

import com.springsecurityjwt.auth.dto.AuthUser;
import org.springframework.security.authentication.AbstractAuthenticationToken;

import java.util.Objects;

public class JwtAuthenticationToken extends AbstractAuthenticationToken {

    private final AuthUser authUser;

    public JwtAuthenticationToken(AuthUser authUser) {
        super(authUser.getAuthorities());
        this.authUser = authUser;
        setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return authUser;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!super.equals(o)) return false;
        if (getClass() != o.getClass()) return false;
        JwtAuthenticationToken that = (JwtAuthenticationToken) o;
        return Objects.equals(authUser, that.authUser);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), authUser);
    }
}
