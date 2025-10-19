package com.backend.bdd;

import com.backend.model.User;
import com.backend.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import com.backend.controller.UserController;
import io.cucumber.java.en.*;
import static org.junit.jupiter.api.Assertions.*;

public class UserLoginSteps {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private UserController userController;

    private ResponseEntity<String> response;

    @Given("a user exists with email {string} and password {string}")
    public void a_user_exists_with_email_and_password(String email, String password) {
        // Clear existing users first to avoid conflicts
        userRepository.deleteAll();

        // Create a unique username for each test run
        String uniqueUsername = "testUser_" + System.currentTimeMillis();
        User testUser = new User(uniqueUsername, email, password);
        userRepository.save(testUser);
    }

    @When("the user attempts to login with email {string} and password {string}")
    public void the_user_attempts_to_login_with_email_and_password(String email, String password) {
        User loginUser = new User();
        loginUser.setEmail(email);
        loginUser.setPassword(password);
        response = userController.login(loginUser);
    }

    @Then("the login should be successful")
    public void the_login_should_be_successful() {
        assertEquals(200, response.getStatusCodeValue());
        assertEquals("Login successful", response.getBody());
    }

    @Then("the login should fail with message {string}")
    public void the_login_should_fail_with_message(String expectedMessage) {
        assertEquals(401, response.getStatusCodeValue()); // or whatever status code you use for failed login
        assertEquals(expectedMessage, response.getBody());
    }
}