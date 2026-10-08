/*
 * SPDX-FileCopyrightText: Copyright © 2021 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.hijacksession.cas;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.HexFormat;
import java.util.LinkedList;
import java.util.Queue;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Supplier;
import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Component;
import org.springframework.web.context.annotation.ApplicationScope;

/**
 * Session identifiers carry a sequence number and a timestamp for traceability, but
 * authentication relies on a 128-bit random component generated with a cryptographically strong
 * generator, so an identifier cannot be predicted from previously observed ones.
 *
 * @author Angel Olle Blazquez
 */
@ApplicationScope
@Component
public class HijackSessionAuthenticationProvider implements AuthenticationProvider<Authentication> {

  private final Queue<String> sessions = new LinkedList<>();
  private static final SecureRandom SECURE_RANDOM = new SecureRandom();
  private static final AtomicLong SEQUENCE =
      new AtomicLong(SECURE_RANDOM.nextLong() & (Long.MAX_VALUE >>> 1));
  protected static final int MAX_SESSIONS = 50;

  private static final Supplier<String> GENERATE_SESSION_ID =
      () -> {
        byte[] random = new byte[16];
        SECURE_RANDOM.nextBytes(random);
        return SEQUENCE.incrementAndGet()
            + "-"
            + Instant.now().toEpochMilli()
            + "-"
            + HexFormat.of().formatHex(random);
      };

  public static final Supplier<Authentication> AUTHENTICATION_SUPPLIER =
      () -> Authentication.builder().id(GENERATE_SESSION_ID.get()).build();

  @Override
  public synchronized Authentication authenticate(Authentication authentication) {
    if (authentication == null) {
      return AUTHENTICATION_SUPPLIER.get();
    }

    if (StringUtils.isNotEmpty(authentication.getId())
        && sessions.contains(authentication.getId())) {
      authentication.setAuthenticated(true);
      return authentication;
    }

    if (StringUtils.isEmpty(authentication.getId())) {
      authentication.setId(GENERATE_SESSION_ID.get());
    }

    authorizedUserAutoLogin();

    return authentication;
  }

  protected void authorizedUserAutoLogin() {
    // simulate other users logging in; their session identifiers are unpredictable
    if (ThreadLocalRandom.current().nextDouble() >= 0.75) {
      Authentication authentication = AUTHENTICATION_SUPPLIER.get();
      authentication.setAuthenticated(true);
      addSession(authentication.getId());
    }
  }

  protected synchronized boolean addSession(String sessionId) {
    if (sessions.size() >= MAX_SESSIONS) {
      sessions.remove();
    }
    return sessions.add(sessionId);
  }

  protected synchronized int getSessionsSize() {
    return sessions.size();
  }
}
