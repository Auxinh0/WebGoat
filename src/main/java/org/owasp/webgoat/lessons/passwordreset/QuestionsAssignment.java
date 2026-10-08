/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.passwordreset;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.util.HashMap;
import java.util.Map;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author nbaars
 * @since 8/20/17.
 */
@RestController
public class QuestionsAssignment implements AssignmentEndpoint {

  /**
   * The answers to the security question are no longer guessable colours: each account has an
   * unpredictable answer that is generated when the application starts and never disclosed.
   */
  private static final Map<String, String> ANSWERS = new HashMap<>();

  static {
    java.security.SecureRandom random = new java.security.SecureRandom();
    for (String user : new String[] {"admin", "jerry", "tom", "larry", "webgoat"}) {
      byte[] bytes = new byte[24];
      random.nextBytes(bytes);
      ANSWERS.put(user, java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(bytes));
    }
  }

  @PostMapping(
      path = "/PasswordReset/questions",
      consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
  @ResponseBody
  public AttackResult passwordReset(@RequestParam Map<String, Object> json) {
    String securityQuestion = (String) json.getOrDefault("securityQuestion", "");
    String username = (String) json.getOrDefault("username", "");

    if ("webgoat".equalsIgnoreCase(username.toLowerCase())) {
      return failed(this).feedback("password-questions-wrong-user").build();
    }

    String validAnswer = ANSWERS.get(username.toLowerCase());
    if (validAnswer == null) {
      return failed(this)
          .feedback("password-questions-unknown-user")
          .feedbackArgs(username)
          .build();
    } else if (java.security.MessageDigest.isEqual(
        validAnswer.getBytes(), securityQuestion.getBytes())) {
      return success(this).build();
    }
    return failed(this).build();
  }
}
