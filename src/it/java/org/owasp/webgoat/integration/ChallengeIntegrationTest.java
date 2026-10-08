/*
 * SPDX-FileCopyrightText: Copyright © 2022 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.integration;

import static org.junit.jupiter.api.Assertions.assertTrue;

import io.restassured.RestAssured;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;

public class ChallengeIntegrationTest extends IntegrationTest {

  @Test
  void testChallenge1() {
    startLesson("Challenge1");

      byte[] resultBytes =
        RestAssured.given()
            .when()
            .relaxedHTTPSValidation()
            .cookie("JSESSIONID", getWebGoatCookie())
            .get(webGoatUrlConfig.url("challenge/logo"))
            .then()
            .statusCode(200)
            .extract()
            .asByteArray();

    String pincode = new String(Arrays.copyOfRange(resultBytes, 81216, 81220));
    Map<String, Object> params = new HashMap<>();
    params.clear();
    params.put("username", "admin");
    params.put("password", "!!webgoat_admin_1234!!".replace("1234", pincode));

      checkAssignment(webGoatUrlConfig.url("challenge/1"), params, true);
      String result =
        RestAssured.given()
            .when()
            .relaxedHTTPSValidation()
            .cookie("JSESSIONID", getWebGoatCookie())
            .formParams(params)
            .post(webGoatUrlConfig.url("challenge/1"))
            .then()
            .statusCode(200)
            .extract()
            .asString();

    String flag = result.substring(result.indexOf("flag") + 6, result.indexOf("flag") + 42);
    params.clear();
    params.put("flag", flag);
      checkAssignment(webGoatUrlConfig.url("challenge/flag/1"), params, true);

    checkResults("Challenge1");

      List<String> capturefFlags =
        RestAssured.given()
            .when()
            .relaxedHTTPSValidation()
            .cookie("JSESSIONID", getWebGoatCookie())
            .get(webGoatUrlConfig.url("scoreboard-data"))
            .then()
            .statusCode(200)
            .extract()
            .jsonPath()
            .get("find { it.username == \"" + this.getUser() + "\" }.flagsCaptured");
    assertTrue(capturefFlags.contains("Admin lost password"));
  }

  @Test
  void testChallenge5() {
    startLesson("Challenge5");

    Map<String, Object> params = new HashMap<>();
    params.clear();
    params.put("username_login", "Larry");
    params.put("password_login", "1' or '1'='1");

    checkAssignment(webGoatUrlConfig.url("challenge/5"), params, false);
  }

  @Test
  void testChallenge7() {
    startLesson("Challenge7");
    cleanMailbox();

    // The former source archive is no longer exposed.
      RestAssured.given()
        .when()
        .relaxedHTTPSValidation()
        .cookie("JSESSIONID", getWebGoatCookie())
        .get(webGoatUrlConfig.url("challenge/7/.git"))
        .then()
        .statusCode(404);

    // The current user can request a one-time link in their own mailbox.
      RestAssured.given()
        .when()
        .relaxedHTTPSValidation()
        .cookie("JSESSIONID", getWebGoatCookie())
        .formParams("email", getUser() + "@webgoat.org")
        .post(webGoatUrlConfig.url("challenge/7"))
        .then()
        .statusCode(200)
        .extract()
        .asString();

    // Check whether email has been received
    var responseBody =
        RestAssured.given()
            .when()
            .relaxedHTTPSValidation()
            .cookie("WEBWOLFSESSION", getWebWolfCookie())
            .get(webWolfUrlConfig.url("mail"))
            .then()
            .extract()
            .response()
            .getBody()
            .asString();
    Assertions.assertThat(responseBody).contains("Hi, you requested a password reset link");

    // The former static admin link cannot redeem a reset or reveal the flag.
      RestAssured.given()
            .when()
            .relaxedHTTPSValidation()
            .cookie("JSESSIONID", getWebGoatCookie())
            .get(webGoatUrlConfig.url("challenge/7/reset-password/{link}"), "375afe1104f4a487a73823c50a9292a2")
            .then()
            .statusCode(HttpStatus.I_AM_A_TEAPOT.value());
  }
}
