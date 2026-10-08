/*
 * SPDX-FileCopyrightText: Copyright © 2020 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.pathtraversal;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.RandomUtils;
import org.owasp.webgoat.container.CurrentUsername;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.FileCopyUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * Serves the cat pictures by a numeric identifier only. The identifier is validated and the file
 * is resolved inside the pictures directory, so no other file on the server can be read, and a
 * missing picture never results in a directory listing. The secret used for the assignment is an
 * unpredictable value that is not derived from the username.
 */
@RestController
@AssignmentHints({
  "path-traversal-profile-retrieve.hint1",
  "path-traversal-profile-retrieve.hint2",
  "path-traversal-profile-retrieve.hint3",
  "path-traversal-profile-retrieve.hint4",
  "path-traversal-profile-retrieve.hint5",
  "path-traversal-profile-retrieve.hint6"
})
@Slf4j
public class ProfileUploadRetrieval implements AssignmentEndpoint {

  private final File catPicturesDirectory;
  private final String secret;

  public ProfileUploadRetrieval(@Value("${webgoat.server.directory}") String webGoatHomeDirectory) {
    this.catPicturesDirectory = new File(webGoatHomeDirectory, "/PathTraversal/" + "/cats");
    this.catPicturesDirectory.mkdirs();
    byte[] bytes = new byte[32];
    new SecureRandom().nextBytes(bytes);
    this.secret = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
  }

  @PostConstruct
  public void initAssignment() {
    for (int i = 1; i <= 10; i++) {
      try (InputStream is =
          new ClassPathResource("lessons/pathtraversal/images/cats/" + i + ".jpg")
              .getInputStream()) {
        FileCopyUtils.copy(is, new FileOutputStream(new File(catPicturesDirectory, i + ".jpg")));
      } catch (Exception e) {
        log.error("Unable to copy pictures" + e.getMessage());
      }
    }
    var secretDirectory = this.catPicturesDirectory.getParentFile().getParentFile();
    try {
      Files.writeString(
          secretDirectory.toPath().resolve("path-traversal-secret.jpg"),
          "You found it, submit the following secret as answer: " + secret);
    } catch (IOException e) {
      log.error("Unable to write secret in: {}", secretDirectory, e);
    }
  }

  @PostMapping("/PathTraversal/random")
  @ResponseBody
  public AttackResult execute(
      @RequestParam(value = "secret", required = false) String secret,
      @CurrentUsername String username) {
    if (secret != null && MessageDigest.isEqual(this.secret.getBytes(), secret.getBytes())) {
      return success(this).build();
    }
    return failed(this).build();
  }

  @GetMapping("/PathTraversal/random-picture")
  @ResponseBody
  public ResponseEntity<?> getProfilePicture(HttpServletRequest request) {
    var id = request.getParameter("id");
    if (id == null) {
      id = String.valueOf(RandomUtils.nextInt(1, 11));
    }
    // only a small numeric identifier selects a picture
    if (!id.matches("[0-9]{1,2}")) {
      return ResponseEntity.badRequest().body("Illegal picture identifier");
    }
    try {
      Path picturesRoot = catPicturesDirectory.toPath().toRealPath();
      Path catPicture = picturesRoot.resolve(id + ".jpg").normalize();
      if (!catPicture.startsWith(picturesRoot) || !Files.isRegularFile(catPicture)) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
      }
      return ResponseEntity.ok()
          .contentType(MediaType.parseMediaType(MediaType.IMAGE_JPEG_VALUE))
          .location(new URI("/PathTraversal/random-picture?id=" + catPicture.getFileName()))
          .body(Base64.getEncoder().encode(Files.readAllBytes(catPicture)));
    } catch (IOException | URISyntaxException e) {
      log.error("Image not found", e);
    }
    return ResponseEntity.badRequest().build();
  }
}
