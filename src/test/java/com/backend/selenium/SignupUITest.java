package com.backend.selenium;

import io.github.bonigarcia.wdm.WebDriverManager;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.WebDriverWait;

import java.time.Duration;

import static org.junit.Assert.assertTrue;

public class SignupUITest {

    private WebDriver driver;
    private WebDriverWait wait;

    @Before
    public void setup() {
        WebDriverManager.chromedriver().setup();
        driver = new ChromeDriver();
        driver.manage().window().maximize();
        wait = new WebDriverWait(driver, Duration.ofSeconds(10));
        driver.get("http://localhost:5173/signup"); // Adjust to your signup page route
    }

    @Test
    public void testSignupSuccess() {
        wait.until(ExpectedConditions.visibilityOfElementLocated(By.name("username")))
                .sendKeys("testuser123");

        driver.findElement(By.name("email")).sendKeys("testuser123@example.com");
        driver.findElement(By.name("password")).sendKeys("password123");

        wait.until(ExpectedConditions.elementToBeClickable(
                By.cssSelector("button.signin-submit-btn"))).click();

        wait.until(ExpectedConditions.visibilityOfElementLocated(
                By.cssSelector("p.signup-message")));

        String message = driver.findElement(By.cssSelector("p.signup-message")).getText();
        assertTrue("Signup failed, got: " + message,
                message.contains("successfully"));
    }

    @After
    public void tearDown() throws InterruptedException {
        Thread.sleep(3000); // keep browser open for debugging
        driver.quit();
    }
}
