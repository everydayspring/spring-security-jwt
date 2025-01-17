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
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.BDDMockito.given;

@ExtendWith(MockitoExtension.class)
public class AuthServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private JwtUtil jwtUtil;

    @InjectMocks
    private AuthService authService;

    @Nested
    class SignupTest {

        @Test
        void successfulSignup() {
            // given
            String username = "testusername";
            String nickname = "testnickname";
            String password = "testpassword";
            String encodedPassword = "$2a$04$jfQeXoc7b5IWWvZFPDE.he56RmITYyjnPA4haWZB2EgFda9uDXsHC";

            User user = new User(username, nickname, encodedPassword, UserRole.USER);
            ReflectionTestUtils.setField(user, "id", 1L);

            given(userRepository.existsByUsername(username)).willReturn(false);
            given(passwordEncoder.encode(password)).willReturn(encodedPassword);
            given(userRepository.save(any(User.class))).willReturn(user);

            // when
            SignupRequest request = new SignupRequest(username, password, nickname);
            SignupResponse response = authService.signup(request);

            // then
            assertNotNull(response);
            assertEquals(username, response.getUsername());
            assertEquals(nickname, response.getNickname());
            assertEquals(1, response.getAuthorities().size());
            assertEquals("ROLE_USER", response.getAuthorities().get(0).getAuthorityName());
        }

        @Test
        void errorWithDuplicateUsername() {
            // given
            String username = "testusername";
            String nickname = "testnickname";
            String password = "testpassword";

            given(userRepository.existsByUsername(anyString())).willReturn(true);

            // when
            SignupRequest request = new SignupRequest(username, nickname, password);
            IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> authService.signup(request));

            // then
            assertEquals("Username is already in use", exception.getMessage());
        }
    }

    @Nested
    class SigninTest {

        @Test
        void successfulSignin() {
            // given
            String username = "testusername";
            String nickname = "testnickname";
            String password = "testpassword";
            String encodedPassword = "$2a$04$jfQeXoc7b5IWWvZFPDE.he56RmITYyjnPA4haWZB2EgFda9uDXsHC";
            String token = "eKDIkdfjoakIdkfjpekdkcjdkoIOdjOKJDFOlLDKFJKL";

            User user = new User(username, nickname, encodedPassword, UserRole.USER);
            ReflectionTestUtils.setField(user, "id", 1L);

            given(userRepository.findByUsername(anyString())).willReturn(Optional.of(user));
            given(passwordEncoder.matches(anyString(), anyString())).willReturn(true);
            given(jwtUtil.createToken(anyLong(), anyString(), anyString(), any(UserRole.class))).willReturn(token);

            // when
            SigninRequest request = new SigninRequest(username, password);
            SigninResponse response = authService.signin(request);

            // then
            assertNotNull(response);
            assertEquals(token, response.getToken());
        }

        @Test
        void errorWithUserNotFound() {
            // given
            String username = "testusername";
            String password = "testpassword";

            given(userRepository.findByUsername(anyString())).willReturn(Optional.empty());

            // when
            SigninRequest request = new SigninRequest(username, password);
            IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> authService.signin(request));

            // then
            assertEquals("Username not found", exception.getMessage());
        }

        @Test
        void errorWithIncorrectPassword() {
            // given
            String username = "testusername";
            String nickname = "testnickname";
            String password = "testpassword";
            String encodedPassword = "$2a$04$jfQeXoc7b5IWWvZFPDE.he56RmITYyjnPA4haWZB2EgFda9uDXsHC";

            User user = new User(username, nickname, encodedPassword, UserRole.USER);
            ReflectionTestUtils.setField(user, "id", 1L);

            given(userRepository.findByUsername(anyString())).willReturn(Optional.of(user));
            given(passwordEncoder.matches(anyString(), anyString())).willReturn(false);

            // when
            SigninRequest request = new SigninRequest(username, password);
            IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> authService.signin(request));

            // then
            assertEquals("Wrong password", exception.getMessage());
        }
    }
}