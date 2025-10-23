package com.backend.controller;

import com.backend.model.User;
import com.backend.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class UserControllerTest {

    @Mock
    private UserRepository userRepository;

    @InjectMocks
    private UserController userController;

    private BCryptPasswordEncoder encoder;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        encoder = new BCryptPasswordEncoder();
    }

    // SIGNUP TESTS

    @Test
    void testSignupNewUser() {
        User user = new User("John", "john@example.com", "password123");

        when(userRepository.existsByEmail(user.getEmail())).thenReturn(false);
        when(userRepository.existsByUsername(user.getUsername())).thenReturn(false);

        ResponseEntity<String> response = userController.signup(user);

        assertEquals(200, response.getStatusCodeValue());
        assertEquals("User registered successfully", response.getBody());
        verify(userRepository, times(1)).save(any(User.class));
    }

    @Test
    void testSignupExistingEmail() {
        User user = new User("Jane", "jane@example.com", "pass123");

        when(userRepository.existsByEmail(user.getEmail())).thenReturn(true);
        when(userRepository.existsByUsername(user.getUsername())).thenReturn(false);

        ResponseEntity<String> response = userController.signup(user);

        assertEquals(400, response.getStatusCodeValue());
        assertEquals("Email already exists", response.getBody());
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    void testSignupExistingUsername() {
        User user = new User("Jane", "jane2@example.com", "pass123");

        when(userRepository.existsByEmail(user.getEmail())).thenReturn(false);
        when(userRepository.existsByUsername(user.getUsername())).thenReturn(true);

        ResponseEntity<String> response = userController.signup(user);

        assertEquals(400, response.getStatusCodeValue());
        assertEquals("Username already exists", response.getBody());
        verify(userRepository, never()).save(any(User.class));
    }

    // LOGIN TESTS

    @Test
    void testLoginSuccess() {
        User loginUser = new User("John", "john@example.com", "password123");
        User storedUser = new User("John", "john@example.com", encoder.encode("password123"));

        when(userRepository.findByEmail(loginUser.getEmail())).thenReturn(storedUser);

        ResponseEntity<String> response = userController.login(loginUser);

        assertEquals(200, response.getStatusCodeValue());
        assertEquals("Login successful", response.getBody());
    }

    @Test
    void testLoginEmailNotFound() {
        User loginUser = new User("John", "john@example.com", "password123");

        when(userRepository.findByEmail(loginUser.getEmail())).thenReturn(null);

        ResponseEntity<String> response = userController.login(loginUser);

        assertEquals(401, response.getStatusCodeValue());
        assertEquals("Invalid credentials", response.getBody());
    }

    @Test
    void testLoginIncorrectPassword() {
        User loginUser = new User("John", "john@example.com", "wrongpassword");
        User storedUser = new User("John", "john@example.com", encoder.encode("password123"));

        when(userRepository.findByEmail(loginUser.getEmail())).thenReturn(storedUser);

        ResponseEntity<String> response = userController.login(loginUser);

        assertEquals(401, response.getStatusCodeValue());
        assertEquals("Invalid credentials", response.getBody());
    }
}
