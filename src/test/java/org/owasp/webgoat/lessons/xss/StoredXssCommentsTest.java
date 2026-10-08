/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.xss;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.hamcrest.CoreMatchers;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

class StoredXssCommentsTest extends LessonTest {

  @Test
  void scriptCommentIsSavedButDoesNotCompleteAssignment() throws Exception {
    ResultActions results =
        mockMvc.perform(
            MockMvcRequestBuilders.post("/CrossSiteScriptingStored/stored-xss")
                .content(
                    "{\"text\":\"someTextHere<script>webgoat.customjs.phoneHome()</script>MoreTextHere\"}")
                .contentType(MediaType.APPLICATION_JSON));

    results.andExpect(status().isOk());
    results.andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));

    mockMvc
        .perform(MockMvcRequestBuilders.get("/CrossSiteScriptingStored/stored-xss"))
        .andExpect(status().isOk())
        .andExpect(
            jsonPath(
                "$[*].text",
                CoreMatchers.hasItem(
                    CoreMatchers.containsString("<script>webgoat.customjs.phoneHome()</script>"))));
  }

  @Test
  void ordinaryCommentIsStillSaved() throws Exception {
    ResultActions results =
        mockMvc.perform(
            MockMvcRequestBuilders.post("/CrossSiteScriptingStored/stored-xss")
                .content("{\"text\":\"A plain comment\"}")
                .contentType(MediaType.APPLICATION_JSON));

    results.andExpect(status().isOk());
    results.andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));

    mockMvc
        .perform(MockMvcRequestBuilders.get("/CrossSiteScriptingStored/stored-xss"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$[*].text", CoreMatchers.hasItem("A plain comment")));
  }

  @Test
  void followUpCannotUseAnUnrelatedNumber() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/CrossSiteScriptingStored/stored-xss-follow-up")
                .param("successMessage", "12345"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  @Test
  void malformedCommentDoesNotCrash() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/CrossSiteScriptingStored/stored-xss")
                .content("not JSON")
                .contentType(MediaType.APPLICATION_JSON))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }
}
