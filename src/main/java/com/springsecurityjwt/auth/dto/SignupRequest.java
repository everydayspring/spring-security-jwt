package com.springsecurityjwt.auth.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
@AllArgsConstructor
public class SignupRequest {

    @Schema(example = "JIN HO")
    @NotBlank
    private String username;
    @Schema(example = "12341234")
    @NotBlank
    private String password;
    @Schema(example = "Mentos")
    @NotBlank
    private String nickname;
}
