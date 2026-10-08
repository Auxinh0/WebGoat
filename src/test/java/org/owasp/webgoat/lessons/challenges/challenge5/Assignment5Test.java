/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.challenges.challenge5;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

class Assignment5Test extends LessonTest {

  @Test
  void passwordSqlInjectionDoesNotAuthenticateLarry() throws Exception {
    for (String payload :
        new String[] {
          "1' or '1'='1", "x' OR 1=1 --", "' UNION SELECT password FROM challenge_users --"
        }) {
      mockMvc
          .perform(
              MockMvcRequestBuilders.post("/challenge/5")
                  .param("username_login", "Larry")
                  .param("password_login", payload))
          .andExpect(status().isOk())
          .andExpect(jsonPath("$.lessonCompleted").value(false));
    }
  }
}
