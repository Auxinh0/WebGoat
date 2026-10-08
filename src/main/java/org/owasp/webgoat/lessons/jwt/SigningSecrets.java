/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.jwt;

import java.security.SecureRandom;
import java.util.Base64;

/** Generates strong, unpredictable HMAC secrets for the JWT lessons at application start. */
public final class SigningSecrets {

  private static final SecureRandom SECURE_RANDOM = new SecureRandom();

  private SigningSecrets() {}

  /** A base64 encoded 512-bit random secret (jjwt interprets HMAC keys as base64). */
  public static String newBase64Secret() {
    byte[] secret = new byte[64];
    SECURE_RANDOM.nextBytes(secret);
    return Base64.getEncoder().encodeToString(secret);
  }

  /** Raw random key bytes of the given length. */
  public static byte[] newKeyBytes(int length) {
    byte[] key = new byte[length];
    SECURE_RANDOM.nextBytes(key);
    return key;
  }

  /** An opaque URL safe random token, e.g. for refresh tokens. */
  public static String newToken() {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(newKeyBytes(32));
  }
}
