package dev.lavalink.youtube.cipher;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.lang.reflect.Field;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class ActionsPatternTest {
  @Test
  void actionsPatternShouldMatchCurrentBaseJsIfPresent() throws Exception {
    String ytEmbedUrl = "https://www.youtube.com/embed/";
    HttpClient client = HttpClient.newHttpClient();
    HttpRequest embedRequest = HttpRequest.newBuilder()
        .uri(URI.create(ytEmbedUrl))
        .GET()
        .build();
    HttpResponse<String> embedResponse = client.send(embedRequest, HttpResponse.BodyHandlers.ofString());
    String embedHtml = embedResponse.body();

    Pattern jsUrlPattern = Pattern.compile("\"jsUrl\":\"([^\"]+)\"");
    Matcher jsUrlMatcher = jsUrlPattern.matcher(embedHtml);
    String baseJsUrl;
    if (jsUrlMatcher.find()) {
      baseJsUrl = jsUrlMatcher.group(1);
      if (baseJsUrl.startsWith("/")) {
        baseJsUrl = "https://www.youtube.com" + baseJsUrl;
      } else if (baseJsUrl.startsWith("//")) {
        baseJsUrl = "https:" + baseJsUrl;
      }
    } else {
      throw new IOException("jsUrl not found in YouTube page source.");
    }

    System.out.println("Downloading base.js from: " + baseJsUrl);

    HttpRequest jsRequest = HttpRequest.newBuilder()
        .uri(URI.create(baseJsUrl))
        .GET()
        .build();
    HttpResponse<String> jsResponse = client.send(jsRequest, HttpResponse.BodyHandlers.ofString());
    String js = jsResponse.body();

    Field f = SignatureCipherManager.class.getDeclaredField("ACTIONS_PATTERN");
    f.setAccessible(true);
    Pattern actionsPattern = (Pattern) f.get(null);

    System.out.println("Testing base.js from URL: " + baseJsUrl);
    System.out.println("Using regex: " + actionsPattern.pattern());

    Matcher matcher = actionsPattern.matcher(js);
    boolean matched = matcher.find();
    if (matched) {
      String snippet = matcher.group(0);
      System.out.println("ACTIONS_PATTERN matched object: variableName=" + matcher.group(1) + ", length=" + snippet.length());
      System.out.println("Beginning: " + snippet.substring(0, Math.min(160, snippet.length())) + "...");
    } else {
      int idxReverse = js.indexOf("reverse(");
      System.out.println("No match found. reverse( index=" + idxReverse + ")");
    }

    assertTrue(matched, "ACTIONS_PATTERN did not match the current base.js");
  }
}
