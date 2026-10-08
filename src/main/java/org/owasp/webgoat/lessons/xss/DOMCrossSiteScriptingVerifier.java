/*
 * SPDX-FileCopyrightText: Copyright © 2016 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.xss;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;

import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/** Created by jason on 11/23/16. */
@RestController
@AssignmentHints(
    value = {
      "xss-dom-message-hint-1",
      "xss-dom-message-hint-2",
      "xss-dom-message-hint-3",
      "xss-dom-message-hint-4",
      "xss-dom-message-hint-5",
      "xss-dom-message-hint-6"
    })
public class DOMCrossSiteScriptingVerifier implements AssignmentEndpoint {

  @PostMapping("/CrossSiteScripting/dom-follow-up")
  @ResponseBody
  public AttackResult completed(@RequestParam String successMessage) {
    return failed(this).feedback("xss-dom-message-failure").build();
  }
}
