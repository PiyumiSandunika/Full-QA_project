package com.backend.api;

import io.restassured.RestAssured;
import org.junit.BeforeClass;
import org.junit.Test;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;

public class LoginApiTest {

    @BeforeClass
    public static void setup() {
        RestAssured.baseURI = "http://localhost:8080/api/users";
    }

    @Test
    public void testLoginSuccess() {
        // adjust credentials to match DB
        given()
                .contentType("application/json")
                .body("{ \"email\": \"john@example.com\", \"password\": \"password123\" }")
                .when()
                .post("/login")
                .then()
                .statusCode(200)
                .contentType("text/plain")
                .body(equalTo("Login successful"));
    }

    @Test
    public void testLoginFailure() {
        given()
                .contentType("application/json")
                .body("{ \"email\": \"wrong@example.com\", \"password\": \"wrongpass\" }")
                .when()
                .post("/login")
                .then()
                .statusCode(401)
                .contentType("text/plain")
                .body(equalTo("User not found"));
    }
}
