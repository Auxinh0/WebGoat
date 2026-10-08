/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.xss;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.hamcrest.CoreMatchers;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

public class DOMCrossSiteScriptingTest extends LessonTest {

  @Test
  void legacyPhoneHomeDoesNotExposeASessionSecret() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/CrossSiteScripting/phone-home-xss")
                .header("webgoat-requested-by", "dom-xss-vuln")
                .param("param1", "42")
                .param("param2", "24"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)))
        .andExpect(
            content().string(CoreMatchers.not(CoreMatchers.containsString("phoneHome Response is"))));
  }

  @Test
  void failure() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/CrossSiteScripting/phone-home-xss")
                .header("webgoat-requested-by", "wrong-value")
                .param("param1", "22")
                .param("param2", "20"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  @Test
  void chromeDevToolsTokenCannotSolveDomFollowUp() throws Exception {
    String response =
        mockMvc
            .perform(MockMvcRequestBuilders.post("/ChromeDevTools/phone-home"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(true)))
            .andReturn()
            .getResponse()
            .getContentAsString();
    String output = new ObjectMapper().readTree(response).path("output").asText();
    String value = output.substring("phoneHome Response is ".length());

    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/CrossSiteScripting/dom-follow-up")
                .param("successMessage", value))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));

    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/ChromeDevTools/dummy").param("successMessage", value))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(true)));
  }
}
