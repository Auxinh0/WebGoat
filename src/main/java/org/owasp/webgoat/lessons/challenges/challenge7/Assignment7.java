/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.challenges.challenge7;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.lessons.challenges.Email;
import org.owasp.webgoat.lessons.challenges.Flags;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.server.ResponseStatusException;

/**
 * @author nbaars
 * @since 4/8/17.
 */
@RestController
public class Assignment7 implements AssignmentEndpoint {

  private static final String TEMPLATE =
      "Hi, you requested a password reset link, please use this <a target='_blank'"
          + " href='%s/challenge/7/reset-password/%s'>link</a> to reset your"
          + " password.\n"
          + " \n\n"
          + "If you did not request this password change you can ignore this message.\n"
          + "If you have any comments or questions, please do not hesitate to reach us at"
          + " support@webgoat-cloud.org\n\n"
          + "Kind regards, \n"
          + "Team WebGoat";

  private final Flags flags;
  private final RestTemplate restTemplate;
  private final String webWolfMailURL;
  private final String webGoatURL;
  private final ConcurrentMap<String, ResetToken> resetTokens = new ConcurrentHashMap<>();

  private record ResetToken(String value, Instant expiresAt) {}

  public Assignment7(
      Flags flags,
      RestTemplate restTemplate,
      @Value("${webwolf.mail.url}") String webWolfMailURL,
      @Value("${webgoat.url}") String webGoatURL) {
    this.flags = flags;
    this.restTemplate = restTemplate;
    this.webWolfMailURL = webWolfMailURL;
    this.webGoatURL = webGoatURL;
  }

  @GetMapping("/challenge/7/reset-password/{link}")
  public ResponseEntity<String> resetPassword(@PathVariable(value = "link") String link) {
    String username = currentUsername();
    ResetToken token = resetTokens.get(username);
    if (token != null
        && Instant.now().isBefore(token.expiresAt())
        && MessageDigest.isEqual(
            token.value().getBytes(StandardCharsets.US_ASCII),
            link.getBytes(StandardCharsets.US_ASCII))
        && resetTokens.remove(username, token)) {
      if ("admin".equalsIgnoreCase(username)) {
        return ResponseEntity.accepted()
            .body(
                "<h1>Success!!</h1>"
                    + "<img src='/WebGoat/images/hi-five-cat.jpg'>"
                    + "<br/><br/>Here is your flag: "
                    + flags.getFlag(7));
      }
      return ResponseEntity.accepted().body("Password reset link redeemed");
    }
    return ResponseEntity.status(HttpStatus.I_AM_A_TEAPOT).body("Reset link invalid or expired");
  }

  @PostMapping("/challenge/7")
  public AttackResult sendPasswordResetLink(@RequestParam String email) {
    String username = currentUsername();
    if (StringUtils.hasText(email) && email.trim().equalsIgnoreCase(username + "@webgoat.org")) {
      String token = new PasswordResetLink().createPasswordReset();
      resetTokens.put(username, new ResetToken(token, Instant.now().plus(Duration.ofMinutes(15))));
      Email mail =
          Email.builder()
              .title("Your password reset link for challenge 7")
              .contents(TEMPLATE.formatted(webGoatURL, token))
              .sender("password-reset@webgoat-cloud.net")
              .recipient(username)
              .time(LocalDateTime.now())
              .build();
      restTemplate.postForEntity(webWolfMailURL, mail, Object.class);
    }
    return failed(this).feedback("email.send").feedbackArgs(email).build();
  }

  private String currentUsername() {
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    if (authentication == null
        || !authentication.isAuthenticated()
        || authentication instanceof AnonymousAuthenticationToken) {
      throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
    }
    return authentication.getName();
  }
}
