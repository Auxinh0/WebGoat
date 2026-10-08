/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.passwordreset;

import static java.util.Optional.ofNullable;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.informationMessage;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.time.LocalDateTime;
import org.owasp.webgoat.container.CurrentUsername;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

/**
 * @author nbaars
 * @since 8/20/17.
 */
@RestController
public class SimpleMailAssignment implements AssignmentEndpoint {
  private static final java.time.Duration RESET_PASSWORD_LIFETIME =
      java.time.Duration.ofMinutes(15);

  private record ResetPassword(String password, java.time.Instant expiresAt) {}

  private static final java.util.Map<String, ResetPassword> resetPasswords =
      new java.util.concurrent.ConcurrentHashMap<>();
  private final java.security.SecureRandom secureRandom = new java.security.SecureRandom();

  private final String webWolfURL;
  private RestTemplate restTemplate;

  public SimpleMailAssignment(
      RestTemplate restTemplate, @Value("${webwolf.mail.url}") String webWolfURL) {
    this.restTemplate = restTemplate;
    this.webWolfURL = webWolfURL;
  }

  @PostMapping(
      path = "/PasswordReset/simple-mail",
      consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
  @ResponseBody
  public AttackResult login(
      @RequestParam String email,
      @RequestParam String password,
      @CurrentUsername String webGoatUsername) {
    String emailAddress = ofNullable(email).orElse("unknown@webgoat.org");
    String username = extractUsername(emailAddress);

    // The temporary password is an unpredictable value mailed to the user; it is single use
    // and expires. It can no longer be derived from the username.
    ResetPassword resetPassword = resetPasswords.get(username);
    if (username.equals(webGoatUsername)
        && resetPassword != null
        && java.time.Instant.now().isBefore(resetPassword.expiresAt())
        && password != null
        && java.security.MessageDigest.isEqual(
            resetPassword.password().getBytes(), password.getBytes())) {
      resetPasswords.remove(username);
      return success(this).build();
    } else {
      return failed(this).feedbackArgs("password-reset-simple.password_incorrect").build();
    }
  }

  @PostMapping(
      consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE,
      value = "/PasswordReset/simple-mail/reset")
  @ResponseBody
  public AttackResult resetPassword(
      @RequestParam String emailReset, @CurrentUsername String username) {
    String email = ofNullable(emailReset).orElse("unknown@webgoat.org");
    return sendEmail(extractUsername(email), email, username);
  }

  private String extractUsername(String email) {
    int index = email.indexOf("@");
    return email.substring(0, index == -1 ? email.length() : index);
  }

  private AttackResult sendEmail(String username, String email, String webGoatUsername) {
    if (username.equals(webGoatUsername)) {
      byte[] bytes = new byte[18];
      secureRandom.nextBytes(bytes);
      String temporaryPassword =
          java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
      resetPasswords.put(
          username,
          new ResetPassword(
              temporaryPassword, java.time.Instant.now().plus(RESET_PASSWORD_LIFETIME)));
      PasswordResetEmail mailEvent =
          PasswordResetEmail.builder()
              .recipient(username)
              .title("Simple e-mail assignment")
              .time(LocalDateTime.now())
              .contents(
                  "Thanks for resetting your password, your new password is: "
                      + temporaryPassword)
              .sender("webgoat@owasp.org")
              .build();
      try {
        restTemplate.postForEntity(webWolfURL, mailEvent, Object.class);
      } catch (RestClientException e) {
        return informationMessage(this)
            .feedback("password-reset-simple.email_failed")
            .output(e.getMessage())
            .build();
      }
      return informationMessage(this)
          .feedback("password-reset-simple.email_send")
          .feedbackArgs(email)
          .build();
    } else {
      return informationMessage(this)
          .feedback("password-reset-simple.email_mismatch")
          .feedbackArgs(username)
          .build();
    }
  }
}
