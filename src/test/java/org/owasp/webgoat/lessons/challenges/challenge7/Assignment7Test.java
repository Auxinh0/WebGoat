/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.challenges.challenge7;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.hamcrest.CoreMatchers;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.owasp.webgoat.lessons.challenges.Email;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpStatus;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.web.client.RestTemplate;

class Assignment7Test extends LessonTest {
  private static final String CHALLENGE_PATH = "/challenge/7";
  private static final String RESET_PASSWORD_PATH = CHALLENGE_PATH + "/reset-password";
  private static final String GIT_PATH = CHALLENGE_PATH + "/.git";

  @MockBean private RestTemplate restTemplate;

  @Value("${webwolf.mail.url}")
  String webWolfMailURL;

  @Test
  @DisplayName("Reset password test")
  void resetPasswordTest() throws Exception {
    ResultActions result =
        mockMvc.perform(MockMvcRequestBuilders.get(RESET_PASSWORD_PATH + "/any"));
    result.andExpect(status().is(equalTo(HttpStatus.I_AM_A_TEAPOT.value())));

    result =
        mockMvc.perform(
            MockMvcRequestBuilders.get(RESET_PASSWORD_PATH + "/375afe1104f4a487a73823c50a9292a2"));
    result.andExpect(status().is(equalTo(HttpStatus.I_AM_A_TEAPOT.value())));
  }

  @Test
  @DisplayName("Send password reset link test")
  void sendPasswordResetLinkTest() throws Exception {
    ResultActions result =
        mockMvc.perform(
            MockMvcRequestBuilders.post(CHALLENGE_PATH)
                .header("Host", "attacker.example")
                .param("email", "test@webgoat.org"));
    result.andExpect(status().isOk());
    result.andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));

    ArgumentCaptor<Email> sentEmail = ArgumentCaptor.forClass(Email.class);
    verify(restTemplate).postForEntity(eq(webWolfMailURL), sentEmail.capture(), eq(Object.class));
    String contents = sentEmail.getValue().getContents();
    org.hamcrest.MatcherAssert.assertThat(contents, not(containsString("attacker.example")));
    Matcher link = Pattern.compile("/reset-password/([A-Za-z0-9_-]{43})").matcher(contents);
    org.junit.jupiter.api.Assertions.assertTrue(link.find());

    mockMvc
        .perform(MockMvcRequestBuilders.get(RESET_PASSWORD_PATH + "/" + link.group(1)))
        .andExpect(status().isAccepted());
    mockMvc
        .perform(MockMvcRequestBuilders.get(RESET_PASSWORD_PATH + "/" + link.group(1)))
        .andExpect(status().is(HttpStatus.I_AM_A_TEAPOT.value()));
  }

  @Test
  void cannotRequestAdminLinkFromAnotherAccount() throws Exception {
    mockMvc
        .perform(MockMvcRequestBuilders.post(CHALLENGE_PATH).param("email", "admin@webgoat.org"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
    verifyNoInteractions(restTemplate);
  }

  @Test
  @DisplayName("git test")
  void gitTest() throws Exception {
    ResultActions result = mockMvc.perform(MockMvcRequestBuilders.get(GIT_PATH));
    result.andExpect(status().isNotFound());
  }
}
