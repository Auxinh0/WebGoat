/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.webwolfintroduction;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Component;

/**
 * Issues the unique codes used by the WebWolf introduction. A code is random, bound to the user
 * and the channel it was issued for, expires after a short time and can be used only once, so it
 * cannot be derived from the username.
 */
@Component
public class UniqueCodes {

  public enum Channel {
    MAIL,
    LANDING
  }

  private static final Duration LIFETIME = Duration.ofMinutes(15);

  private record PendingCode(String code, Instant expiresAt) {}

  private final SecureRandom secureRandom = new SecureRandom();
  private final Map<String, PendingCode> pending = new ConcurrentHashMap<>();

  public String issue(String username, Channel channel) {
    byte[] bytes = new byte[24];
    secureRandom.nextBytes(bytes);
    String code = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    pending.put(key(username, channel), new PendingCode(code, Instant.now().plus(LIFETIME)));
    return code;
  }

  public boolean redeem(String username, Channel channel, String candidate) {
    if (candidate == null || username == null) {
      return false;
    }
    PendingCode pendingCode = pending.get(key(username, channel));
    if (pendingCode == null || Instant.now().isAfter(pendingCode.expiresAt())) {
      pending.remove(key(username, channel));
      return false;
    }
    boolean matches = MessageDigest.isEqual(pendingCode.code().getBytes(), candidate.getBytes());
    if (matches) {
      pending.remove(key(username, channel));
    }
    return matches;
  }

  private static String key(String username, Channel channel) {
    return channel.name() + ":" + username;
  }
}
