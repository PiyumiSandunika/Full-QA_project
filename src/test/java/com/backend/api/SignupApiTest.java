package com.backend.api;

import io.restassured.RestAssured;
import org.junit.BeforeClass;
import org.junit.Test;

import java.util.UUID;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;

public class SignupApiTest {

    @BeforeClass
    public static void setup() {
        RestAssured.baseURI = "http://localhost:8080/api/users";
    }

    @Test
    public void testSignupSuccess() {
        String randomUsername = "user_" + UUID.randomUUID();
        String randomEmail = randomUsername + "@example.com";

        given()
                .contentType("application/json")
                .body("{ \"username\": \"" + randomUsername + "\", " +
                        "\"email\": \"" + randomEmail + "\", " +
                        "\"password\": \"pass123\" }")
                .when()
                .post("/signup")
                .then()
                .statusCode(200)
                .contentType("text/plain")
                .body(equalTo("User registered successfully"));
    }

}
