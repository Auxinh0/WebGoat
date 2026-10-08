/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.csrf;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.is;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

class ForgedReviewsTest extends LessonTest {

  @BeforeEach
  void setup() {
    mockMvc = MockMvcBuilders.webAppContextSetup(wac).build();
  }

  @Test
  void crossSiteRequestCannotStoreAReview() throws Exception {
    String text = "forged-" + UUID.randomUUID();
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/csrf/review")
                .header("Host", "localhost:8080")
                .header("Origin", "http://attacker.example")
                .param("reviewText", text)
                .param("stars", "5"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));

    String reviews =
        mockMvc.perform(MockMvcRequestBuilders.get("/csrf/review"))
            .andExpect(status().isOk())
            .andReturn()
            .getResponse()
            .getContentAsString();
    assertThat(reviews).doesNotContain(text);
  }

  @Test
  void sameOriginRequestStoresAReview() throws Exception {
    String text = "legitimate-" + UUID.randomUUID();
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/csrf/review")
                .header("Host", "localhost:8080")
                .header("Origin", "http://localhost:8080")
                .param("reviewText", text)
                .param("stars", "5"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));

    String reviews =
        mockMvc.perform(MockMvcRequestBuilders.get("/csrf/review"))
            .andExpect(status().isOk())
            .andReturn()
            .getResponse()
            .getContentAsString();
    assertThat(reviews).contains(text);
  }
}
