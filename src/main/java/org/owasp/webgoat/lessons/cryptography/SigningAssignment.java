/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.cryptography;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import jakarta.servlet.http.HttpServletRequest;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import javax.xml.bind.DatatypeConverter;
import lombok.extern.slf4j.Slf4j;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * The verifier keeps its own RSA key pair in the server session and never hands out the private
 * half. The key material published to the browser is a separate practice key that is not trusted
 * by the verifier, so possessing it does not allow producing an accepted signature.
 */
@RestController
@AssignmentHints({
  "crypto-signing.hints.1",
  "crypto-signing.hints.2",
  "crypto-signing.hints.3",
  "crypto-signing.hints.4"
})
@Slf4j
public class SigningAssignment implements AssignmentEndpoint {

  private static final String TRUSTED_KEY_PAIR = "signingTrustedKeyPair";

  @RequestMapping(path = "/crypto/signing/getprivate", produces = MediaType.TEXT_HTML_VALUE)
  @ResponseBody
  public String getPrivateKey(HttpServletRequest request)
      throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
    // make sure the verifier has a trusted key pair for this session
    trustedKeyPair(request);
    // the key returned to the client is a practice key only, unrelated to the trusted key pair
    KeyPair practiceKeyPair = CryptoUtil.generateKeyPair();
    return CryptoUtil.getPrivateKeyInPEM(practiceKeyPair);
  }

  @RequestMapping(path = "/crypto/signing/getpublic", produces = MediaType.TEXT_PLAIN_VALUE)
  @ResponseBody
  public String getPublicKey(HttpServletRequest request)
      throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
    KeyPair keyPair = trustedKeyPair(request);
    return "-----BEGIN PUBLIC KEY-----\n"
        + Base64.getMimeEncoder(64, "\n".getBytes())
            .encodeToString(keyPair.getPublic().getEncoded())
        + "\n-----END PUBLIC KEY-----\n";
  }

  @PostMapping("/crypto/signing/verify")
  @ResponseBody
  public AttackResult completed(
      HttpServletRequest request, @RequestParam String modulus, @RequestParam String signature) {

    KeyPair keyPair = (KeyPair) request.getSession().getAttribute(TRUSTED_KEY_PAIR);
    if (keyPair == null || modulus == null || signature == null) {
      return failed(this).feedback("crypto-signing.notok").build();
    }
    String tempModulus = modulus;
    RSAPublicKey rsaPubKey = (RSAPublicKey) keyPair.getPublic();
    if (tempModulus.length() == 512) {
      tempModulus = "00".concat(tempModulus);
    }
    if (!DatatypeConverter.printHexBinary(rsaPubKey.getModulus().toByteArray())
        .equals(tempModulus.toUpperCase())) {
      log.warn("modulus {} incorrect", modulus);
      return failed(this).feedback("crypto-signing.modulusnotok").build();
    }
    /* the signature is only accepted when it was produced with the trusted private key */
    if (CryptoUtil.verifyMessage(modulus, signature, keyPair.getPublic())) {
      return success(this).feedback("crypto-signing.success").build();
    } else {
      log.warn("signature incorrect");
      return failed(this).feedback("crypto-signing.notok").build();
    }
  }

  private KeyPair trustedKeyPair(HttpServletRequest request)
      throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
    KeyPair keyPair = (KeyPair) request.getSession().getAttribute(TRUSTED_KEY_PAIR);
    if (keyPair == null) {
      keyPair = CryptoUtil.generateKeyPair();
      request.getSession().setAttribute(TRUSTED_KEY_PAIR, keyPair);
    }
    return keyPair;
  }
}
