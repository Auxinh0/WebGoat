/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.idor;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.container.session.LessonSession;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
@AssignmentHints({
  "idor.hints.otherProfile1",
  "idor.hints.otherProfile2",
  "idor.hints.otherProfile3",
  "idor.hints.otherProfile4",
  "idor.hints.otherProfile5",
  "idor.hints.otherProfile6",
  "idor.hints.otherProfile7",
  "idor.hints.otherProfile8",
  "idor.hints.otherProfile9"
})
public class IDOREditOtherProfile implements AssignmentEndpoint {

  private final LessonSession userSessionData;

  public IDOREditOtherProfile(LessonSession lessonSession) {
    this.userSessionData = lessonSession;
  }

  @PutMapping(path = "/IDOR/profile/{userId}", consumes = "application/json")
  @ResponseBody
  public AttackResult completed(
      @PathVariable("userId") String userId, @RequestBody UserProfile userSubmittedProfile) {
    String ownId = IDORAccessPolicy.requireLessonUserId(userSessionData);
    if (!ownId.equals(userId) && !IDORAccessPolicy.isWebGoatAdmin()) {
      return failed(this).feedback("idor.edit.profile.failure4").build();
    }
    if (userSubmittedProfile.getUserId() != null
        && !userId.equals(userSubmittedProfile.getUserId())) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
    }

    UserProfile profile = IDORAccessPolicy.getProfile(userSessionData, userId);
    // Only public profile fields can be changed. The submitted role and admin flag are ignored.
    if (userSubmittedProfile.getColor() != null) {
      profile.setColor(userSubmittedProfile.getColor());
    }
    if (userSubmittedProfile.getSize() != null) {
      profile.setSize(userSubmittedProfile.getSize());
    }
    userSessionData.setValue("idor-profile-" + userId, profile);

    if (IDORAccessPolicy.isWebGoatAdmin() && !ownId.equals(userId)) {
      return success(this)
          .feedback("idor.edit.profile.success1")
          .output(profile.profileToMap().toString())
          .build();
    }
    return failed(this)
        .feedback("idor.edit.profile.failure4")
        .output(profile.publicProfileToMap().toString())
        .build();
  }
}
