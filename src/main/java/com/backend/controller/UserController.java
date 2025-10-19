package com.backend.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import com.backend.model.User;
import com.backend.repository.UserRepository;

@CrossOrigin(origins = "http://localhost:5173")
@RestController
@RequestMapping("/api/users")
public class UserController {

    @Autowired
    private UserRepository userRepository;

    // Use one consistent encoder
    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

    // ✅ Signup with ResponseEntity
    @PostMapping("/signup")
    public ResponseEntity<String> signup(@RequestBody User user) {
        boolean emailExists = userRepository.existsByEmail(user.getEmail());
        boolean usernameExists = userRepository.existsByUsername(user.getUsername());

        if (emailExists && usernameExists) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Both email and username already exist");
        } else if (emailExists) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Email already exists");
        } else if (usernameExists) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Username already exists");
        }

        // Hash password before saving
        user.setPassword(encoder.encode(user.getPassword()));
        userRepository.save(user);

        return ResponseEntity.ok("User registered successfully");
    }

    // ✅ Login with password hashing check
    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody User loginUser) {
        User user = userRepository.findByEmail(loginUser.getEmail());
        if (user == null || !encoder.matches(loginUser.getPassword(), user.getPassword())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials");
        }

        return ResponseEntity.ok("Login successful");
    }
}
