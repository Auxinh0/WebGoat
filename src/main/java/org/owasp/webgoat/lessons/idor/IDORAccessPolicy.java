/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.idor;

import org.owasp.webgoat.container.session.LessonSession;
import org.owasp.webgoat.container.users.WebGoatUser;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.server.ResponseStatusException;

final class IDORAccessPolicy {

  static final String TOM_ID = "2342384";

  private IDORAccessPolicy() {}

  static String requireWebGoatUsername() {
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    if (authentication == null
        || !authentication.isAuthenticated()
        || authentication instanceof AnonymousAuthenticationToken) {
      throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
    }
    return authentication.getName();
  }

  static String requireLessonUserId(LessonSession session) {
    requireWebGoatUsername();
    if (!"tom".equals(session.getValue("idor-authenticated-as"))
        || !TOM_ID.equals(session.getValue("idor-authenticated-user-id"))) {
      throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
    }
    return TOM_ID;
  }

  static boolean isWebGoatAdmin() {
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    return authentication != null
        && authentication.isAuthenticated()
        && !(authentication instanceof AnonymousAuthenticationToken)
        && authentication.getPrincipal() instanceof WebGoatUser
        && authentication.getAuthorities().stream()
            .anyMatch(authority -> WebGoatUser.ROLE_ADMIN.equals(authority.getAuthority()));
  }

  static void requireProfileAccess(LessonSession session, String userId) {
    String ownId = requireLessonUserId(session);
    if (!ownId.equals(userId) && !isWebGoatAdmin()) {
      throw new ResponseStatusException(HttpStatus.FORBIDDEN);
    }
  }

  static UserProfile getProfile(LessonSession session, String userId) {
    Object saved = session.getValue("idor-profile-" + userId);
    if (saved instanceof UserProfile profile && userId.equals(profile.getUserId())) {
      return profile;
    }
    UserProfile profile = new UserProfile(userId);
    if (profile.getUserId() == null) {
      throw new ResponseStatusException(HttpStatus.NOT_FOUND);
    }
    return profile;
  }
}
