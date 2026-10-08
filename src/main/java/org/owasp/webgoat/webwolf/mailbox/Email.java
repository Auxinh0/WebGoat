/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.webwolf.mailbox;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import java.io.Serializable;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.jsoup.Jsoup;
import org.jsoup.safety.Safelist;

/**
 * @author nbaars
 * @since 8/20/17.
 */
@Data
@Builder
@AllArgsConstructor
@Entity
@NoArgsConstructor
public class Email implements Serializable {

  private static final Safelist SAFE_MAIL_HTML =
      Safelist.none()
          .addTags("a")
          .addAttributes("a", "href")
          .addProtocols("a", "href", "http", "https")
          .addEnforcedAttribute("a", "target", "_blank")
          .addEnforcedAttribute("a", "rel", "noopener noreferrer");

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @JsonIgnore private LocalDateTime time = LocalDateTime.now();

  @Column(length = 1024)
  private String contents;

  private String sender;
  private String title;
  private String recipient;

  @JsonIgnore
  public String getSafeContents() {
    if (contents == null) {
      return "";
    }
    return Jsoup.isValid(contents, SAFE_MAIL_HTML)
        ? contents
        : Jsoup.clean(contents, SAFE_MAIL_HTML);
  }

  public String getSummary() {
    return "-" + this.contents.substring(0, Math.min(50, contents.length()));
  }

  public LocalDateTime getTimestamp() {
    return time;
  }

  public String getTime() {
    return DateTimeFormatter.ofPattern("h:mm a").format(time);
  }

  public String getShortSender() {
    return sender.substring(0, sender.indexOf("@"));
  }
}
