/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.idor;

import java.util.Map;
import org.owasp.webgoat.container.session.LessonSession;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class IDORViewOwnProfile {

  private final LessonSession userSessionData;

  public IDORViewOwnProfile(LessonSession userSessionData) {
    this.userSessionData = userSessionData;
  }

  @GetMapping(
      path = {"/IDOR/own", "/IDOR/profile"},
      produces = {"application/json"})
  @ResponseBody
  public Map<String, Object> invoke() {
    String authUserId = IDORAccessPolicy.requireLessonUserId(userSessionData);
    return IDORAccessPolicy.getProfile(userSessionData, authUserId).publicProfileToMap();
  }
}
