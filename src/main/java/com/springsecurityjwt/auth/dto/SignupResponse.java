package com.springsecurityjwt.auth.dto;

import com.springsecurityjwt.user.enums.UserRole;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class SignupResponse {

    private String username;
    private String nickname;
    private List<Authority> authorities;

    @Data
    @AllArgsConstructor
    @NoArgsConstructor
    public static class Authority {
        private String authorityName;

        public static Authority fromUserRole(UserRole userRole) {
            return new Authority(userRole.getAuthority());
        }
    }
}
