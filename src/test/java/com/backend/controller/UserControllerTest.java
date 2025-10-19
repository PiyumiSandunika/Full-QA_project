//package com.backend.controller;
//
//import com.backend.model.User;
//import com.backend.repository.UserRepository;
//import org.junit.jupiter.api.BeforeEach;
//import org.junit.jupiter.api.Test;
//import org.mockito.InjectMocks;
//import org.mockito.Mock;
//import org.mockito.MockitoAnnotations;
//
//import static org.junit.jupiter.api.Assertions.*;
//import static org.mockito.Mockito.*;
//
//class UserControllerTest {
//
//    @Mock
//    private UserRepository userRepository;
//
//    @InjectMocks
//    private UserController userController;
//
//    @BeforeEach
//    void setUp() {
//        MockitoAnnotations.openMocks(this);
//    }
//
//    // SIGNUP FEATURE TESTS
//
//    // Test signup with a new user (Red: fails if signup logic not implemented)
//    @Test
//    void testSignupNewUser() {
//        User user = new User("John", "john@example.com", "password123");
//
//        when(userRepository.existsByEmail(user.getEmail())).thenReturn(false);
//        when(userRepository.existsByUsername(user.getUsername())).thenReturn(false);
//
//        String response = userController.signup(user);
//
//        assertEquals("User registered successfully", response);
//        verify(userRepository, times(1)).save(user);
//    }
//
//    // Test signup with existing email
//    @Test
//    void testSignupExistingEmail() {
//        User user = new User("Jane", "jane@example.com", "pass123");
//
//        when(userRepository.existsByEmail(user.getEmail())).thenReturn(true);
//
//        String response = userController.signup(user);
//
//        assertEquals("Email already exists", response);
//        verify(userRepository, never()).save(user);
//    }
//
//    // Test signup with existing username
//    @Test
//    void testSignupExistingUsername() {
//        User user = new User("Jane", "jane2@example.com", "pass123");
//
//        when(userRepository.existsByEmail(user.getEmail())).thenReturn(false);
//        when(userRepository.existsByUsername(user.getUsername())).thenReturn(true);
//
//        String response = userController.signup(user);
//
//        assertEquals("Username already exists", response);
//        verify(userRepository, never()).save(user);
//    }
//
//
//    // LOGIN FEATURE TESTS
//
//
//    @Test
//    void testLoginSuccess() {
//        User loginUser = new User("John", "john@example.com", "password123");
//        User storedUser = new User("John", "john@example.com", "password123");
//
//        when(userRepository.findByEmail(loginUser.getEmail())).thenReturn(storedUser);
//
//        var response = userController.login(loginUser);
//
//        assertEquals(200, response.getStatusCodeValue());
//        assertEquals("Login successful", response.getBody());
//    }
//
//    @Test
//    void testLoginEmailNotFound() {
//        User loginUser = new User("John", "john@example.com", "password123");
//
//        when(userRepository.findByEmail(loginUser.getEmail())).thenReturn(null);
//
//        var response = userController.login(loginUser);
//
//        assertEquals(401, response.getStatusCodeValue());
//        assertEquals("User not found", response.getBody());
//    }
//
//    @Test
//    void testLoginIncorrectPassword() {
//        User loginUser = new User("John", "john@example.com", "wrongpassword");
//        User storedUser = new User("John", "john@example.com", "password123");
//
//        when(userRepository.findByEmail(loginUser.getEmail())).thenReturn(storedUser);
//
//        var response = userController.login(loginUser);
//
//        assertEquals(401, response.getStatusCodeValue());
//        assertEquals("Incorrect password", response.getBody());
//    }
//
//}
