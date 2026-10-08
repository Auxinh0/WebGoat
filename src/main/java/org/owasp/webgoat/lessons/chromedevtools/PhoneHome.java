/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.chromedevtools;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.security.SecureRandom;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.container.session.LessonSession;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class PhoneHome implements AssignmentEndpoint {

  private static final SecureRandom RANDOM = new SecureRandom();
  private final LessonSession lessonSession;

  public PhoneHome(LessonSession lessonSession) {
    this.lessonSession = lessonSession;
  }

  @PostMapping("/ChromeDevTools/phone-home")
  @ResponseBody
  public AttackResult completed() {
    String value = String.valueOf(RANDOM.nextInt());
    lessonSession.setValue("chromeDevToolsRandValue", value);
    return success(this).output("phoneHome Response is " + value).build();
  }
}
