/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.htmltampering;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.informationMessage;

import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({"hint1", "hint2", "hint3"})
public class HtmlTamperingTask implements AssignmentEndpoint {

  @PostMapping("/HtmlTampering/task")
  @ResponseBody
  public AttackResult completed(@RequestParam String QTY, @RequestParam String Total) {
    int quantity;
    java.math.BigDecimal submittedTotal;
    try {
      quantity = Integer.parseInt(QTY.trim());
      submittedTotal = new java.math.BigDecimal(Total.trim());
    } catch (NumberFormatException e) {
      return failed(this).feedback("html-tampering.tamper.failure").build();
    }
    if (quantity < 1 || quantity > 1000) {
      return failed(this).feedback("html-tampering.tamper.failure").build();
    }
    // The total is never trusted from the client: it is recomputed from the catalogue price
    // and any mismatch (such as a lowered hidden field) is rejected.
    java.math.BigDecimal expectedTotal =
        new java.math.BigDecimal("2999.99").multiply(java.math.BigDecimal.valueOf(quantity));
    if (expectedTotal.compareTo(submittedTotal) != 0) {
      return failed(this).feedback("html-tampering.tamper.failure").build();
    }
    return informationMessage(this)
        .output("Order accepted for " + quantity + " item(s), total " + expectedTotal)
        .build();
  }
}
