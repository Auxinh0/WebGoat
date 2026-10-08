/*
 * SPDX-FileCopyrightText: Copyright © 2020 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.integration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.is;

import io.restassured.RestAssured;
import io.restassured.http.ContentType;
import java.util.Map;
import org.apache.http.HttpStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class IDORIntegrationTest extends IntegrationTest {

  @BeforeEach
  public void init() {
    startLesson("IDOR");
  }

  @Test
  void lessonProfileAccessIsLimitedToTheAuthenticatedUser() {
    RestAssured.given()
        .relaxedHTTPSValidation()
        .cookie("JSESSIONID", getWebGoatCookie())
        .get(webGoatUrlConfig.url("IDOR/profile"))
        .then()
        .statusCode(HttpStatus.SC_UNAUTHORIZED);

    checkAssignment(
        webGoatUrlConfig.url("IDOR/login"), Map.of("username", "tom", "password", "cat"), true);

    Map<String, Object> ownProfile =
        RestAssured.given()
            .relaxedHTTPSValidation()
            .cookie("JSESSIONID", getWebGoatCookie())
            .get(webGoatUrlConfig.url("IDOR/profile"))
            .then()
            .statusCode(HttpStatus.SC_OK)
            .extract()
            .jsonPath()
            .getMap("$");
    assertThat(ownProfile)
        .containsEntry("name", "Tom Cat")
        .doesNotContainKeys("userId", "role");

    Boolean exposedAttributesCompleted =
        RestAssured.given()
            .relaxedHTTPSValidation()
            .cookie("JSESSIONID", getWebGoatCookie())
            .formParam("attributes", "userId,role")
            .post(webGoatUrlConfig.url("IDOR/diff-attributes"))
            .then()
            .statusCode(HttpStatus.SC_OK)
            .extract()
            .path("lessonCompleted");
    assertThat(exposedAttributesCompleted).isFalse();

    checkAssignment(
        webGoatUrlConfig.url("IDOR/profile/alt-path"),
        Map.of("url", "WebGoat/IDOR/profile/2342384"),
        false);

    RestAssured.given()
        .relaxedHTTPSValidation()
        .cookie("JSESSIONID", getWebGoatCookie())
        .formParam("url", "WebGoat/IDOR/profile/2342388")
        .post(webGoatUrlConfig.url("IDOR/profile/alt-path"))
        .then()
        .statusCode(HttpStatus.SC_OK)
        .body("lessonCompleted", is(false));
    RestAssured.given()
        .relaxedHTTPSValidation()
        .cookie("JSESSIONID", getWebGoatCookie())
        .get(webGoatUrlConfig.url("IDOR/profile/2342388"))
        .then()
        .statusCode(HttpStatus.SC_OK)
        .body("lessonCompleted", is(false));
    RestAssured.given()
        .relaxedHTTPSValidation()
        .cookie("JSESSIONID", getWebGoatCookie())
        .contentType(ContentType.JSON)
        .body(
            "{\"role\":1,\"color\":\"red\",\"size\":\"large\",\"name\":\"Buffalo Bill\","
                + "\"userId\":\"2342388\"}")
        .put(webGoatUrlConfig.url("IDOR/profile/2342388"))
        .then()
        .statusCode(HttpStatus.SC_OK)
        .body("lessonCompleted", is(false));
  }
}
