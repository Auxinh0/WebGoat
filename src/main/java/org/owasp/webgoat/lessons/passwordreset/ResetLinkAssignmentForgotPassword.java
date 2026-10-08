/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.passwordreset;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.informationMessage;

import java.time.Instant;
import java.util.Locale;
import java.util.UUID;
import org.owasp.webgoat.container.CurrentUsername;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.client.RestClientException;

/**
 * Part of the password reset assignment. Used to send the e-mail.
 *
 * @author nbaars
 * @since 8/20/17.
 */
@RestController
public class ResetLinkAssignmentForgotPassword implements AssignmentEndpoint {

  private final RestTemplate restTemplate;
  private final String webGoatURL;
  private final String webWolfURL;
  private final String webWolfMailURL;

  public ResetLinkAssignmentForgotPassword(
      RestTemplate restTemplate,
      @Value("${webgoat.url}") String webGoatURL,
      @Value("${webwolf.url}") String webWolfURL,
      @Value("${webwolf.mail.url}") String webWolfMailURL) {
    this.restTemplate = restTemplate;
    this.webGoatURL = webGoatURL.replaceAll("/+$", "");
    this.webWolfURL = webWolfURL.replaceAll("/+$", "");
    this.webWolfMailURL = webWolfMailURL;
  }

  @PostMapping("/PasswordReset/ForgotPassword/create-password-reset-link")
  @ResponseBody
  public AttackResult sendPasswordResetLink(
      @RequestParam String email, @CurrentUsername String username) {
    String normalizedEmail = email.trim().toLowerCase(Locale.ROOT);
    String ownMailbox = username.toLowerCase(Locale.ROOT) + "@webgoat.org";
    if (!ownMailbox.equals(normalizedEmail)
        && !ResetLinkAssignment.TOM_EMAIL.equals(normalizedEmail)) {
      // Only lesson mailboxes can receive a token; the reply does not reveal whether one was sent.
      return informationMessage(this).feedback("email.send").feedbackArgs(email).build();
    }
    // A poisoned Host header cannot change the reset recipient or trusted link.
    String resetLink = UUID.randomUUID().toString();
    String owner = normalizedEmail.substring(0, normalizedEmail.indexOf('@'));
    synchronized (ResetLinkAssignment.resetLinks) {
      ResetLinkAssignment.resetLinks.put(
          resetLink,
          new ResetLinkAssignment.ResetLink(
              owner, normalizedEmail, Instant.now().plus(ResetLinkAssignment.RESET_LINK_LIFETIME)));
    }
    try {
      sendMailToUser(normalizedEmail, resetLink);
    } catch (Exception e) {
      ResetLinkAssignment.resetLinks.remove(resetLink);
      return failed(this).output("E-mail can't be send. please try again.").build();
    }

    if (ResetLinkAssignment.TOM_EMAIL.equals(normalizedEmail)) {
      try {
        // WebWolf records this visit; its response does not determine whether mail was delivered.
        restTemplate.getForEntity(
            webWolfURL + "/PasswordReset/reset/reset-password/" + resetLink, String.class);
      } catch (RestClientException ignored) {
        // The simulated visit has no matching page in WebWolf.
      }
    }

    // Delivering a link is not proof that the requester controls the mailbox.
    return informationMessage(this).feedback("email.send").feedbackArgs(email).build();
  }

  private void sendMailToUser(String email, String resetLink) {
    int index = email.indexOf("@");
    String username = email.substring(0, index == -1 ? email.length() : index);
    PasswordResetEmail mail =
        PasswordResetEmail.builder()
            .title("Your password reset link")
            .contents(String.format(ResetLinkAssignment.TEMPLATE, webGoatURL, resetLink))
            .sender("password-reset@webgoat-cloud.net")
            .recipient(username)
            .build();
    this.restTemplate.postForEntity(webWolfMailURL, mail, Object.class);
  }
}
