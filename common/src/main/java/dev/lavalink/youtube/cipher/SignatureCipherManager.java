package dev.lavalink.youtube.cipher;

import com.sedmelluq.discord.lavaplayer.tools.DataFormatTools;
import com.sedmelluq.discord.lavaplayer.tools.ExceptionTools;
import com.sedmelluq.discord.lavaplayer.tools.io.HttpClientTools;
import com.sedmelluq.discord.lavaplayer.tools.io.HttpInterface;
import dev.lavalink.youtube.YoutubeSource;
import dev.lavalink.youtube.cipher.ScriptExtractionException.ExtractionFailureType;
import dev.lavalink.youtube.track.format.StreamFormat;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.util.EntityUtils;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.mozilla.javascript.engine.RhinoScriptEngineFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.script.ScriptEngine;
import javax.script.ScriptException;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import static com.sedmelluq.discord.lavaplayer.tools.ExceptionTools.throwWithDebugInfo;

/**
 * Handles parsing and caching of signature ciphers
 */
@SuppressWarnings({"RegExpRedundantEscape", "RegExpUnnecessaryNonCapturingGroup"})
public class SignatureCipherManager {
  private static final Logger log = LoggerFactory.getLogger(SignatureCipherManager.class);

  private static final String VARIABLE_PART = "[a-zA-Z_\\$][a-zA-Z_0-9\\$]*";
  private static final String VARIABLE_PART_OBJECT_DECLARATION = "[\"']?[a-zA-Z_\\$][a-zA-Z_0-9\\$]*[\"']?";

  private static final Pattern TIMESTAMP_PATTERN = Pattern.compile("(signatureTimestamp|sts):(\\d+)");

  // Dodano let|const oraz nieco szerszy dopuszczalny zakres wartości (pozostawiono oryginalne alternatywy)
  private static final Pattern GLOBAL_VARS_PATTERN = Pattern.compile(
          "(?:'use\\s+strict';)?(?<code>(?:var|let|const)\\s*(?<varname>[A-Za-z0-9_$]+)\\s*=\\s*(?:'[^']+'|\"[^\"]+\")\\.split\\((?:\"\"|'')\\))"


  );

  // Zmieniono: var -> (?:var|let|const) oraz >=3 funkcje (co najmniej 3) w obiekcie; dopuszczono opcjonalną średnik
  private static final Pattern ACTIONS_PATTERN = Pattern.compile(
      "(?:var|let|const)\\s+([$A-Za-z0-9_]+)\\s*=\\s*\\{" +
          "(?:\\s*" + VARIABLE_PART_OBJECT_DECLARATION + "\\s*:\\s*function\\s*\\([^)]*\\)\\s*\\{.*?}\\s*,){2,}" +
          "\\s*" + VARIABLE_PART_OBJECT_DECLARATION + "\\s*:\\s*function\\s*\\([^)]*\\)\\s*\\{.*?}\\s*};?",
      Pattern.DOTALL
  );

  // Rozszerzony wzorzec: delegujący (return innej funkcji), inline split/join, lub prosty return parametru
  private static final Pattern SIG_FUNCTION_PATTERN = Pattern.compile(
      "(" +
          "function(?:\\s+" + VARIABLE_PART + ")?\\s*\\(\\s*" + VARIABLE_PART + "(?:\\s*,[^)]*)?\\)\\s*\\{\\s*return\\s*" + VARIABLE_PART + "\\([^)]*\\);?\\s*\\}" +
      ")|(" +
          "function(?:\\s+" + VARIABLE_PART + ")?\\s*\\(\\s*(" + VARIABLE_PART + ")(?:\\s*,[^)]*)?\\)\\s*\\{[^{}]*?\\3=\\3\\.split\\(\\\"\\\"\\);.*?return\\s+\\3\\.join\\(\\\"\\\"\\)\\s*;?\\}" +
      ")|(" +
          "function(?:\\s+" + VARIABLE_PART + ")?\\s*\\(\\s*(" + VARIABLE_PART + ")(?:\\s*,[^)]*)?\\)\\s*\\{[^{}]*?return\\s+\\5\\s*;?\\}" +
      ")",
      Pattern.DOTALL
  );

  // N function: dopuszczono opcjonalną nazwę oraz let|const
  private static final Pattern N_FUNCTION_PATTERN = Pattern.compile(
      "function(?:\\s+" + VARIABLE_PART + ")?\\(\\s*(" + VARIABLE_PART + ")\\s*\\)\\s*\\{" +
          "(?:var|let|const)\\s*(" + VARIABLE_PART + ")=\\1\\[" + VARIABLE_PART + "\\[\\d+\\]\\]\\(" + VARIABLE_PART + "\\[\\d+\\]\\)" +
          ".*?catch\\(\\s*(\\w+)\\s*\\)\\s*\\{" +
          "\\s*return.*?\\+\\s*\\1\\s*}" +
          "\\s*return\\s*\\2\\[" + VARIABLE_PART + "\\[\\d+\\]\\]\\(" + VARIABLE_PART + "\\[\\d+\\]\\)\\};",
      Pattern.DOTALL
  );

  // Bardziej liberalny fallback dla n funkcji: szukamy funkcji z try/catch i zwrotem z dodaniem zmiennej z catch lub parametru
  private static final Pattern N_FUNCTION_FALLBACK_PATTERN = Pattern.compile(
      "function(?:\\s+" + VARIABLE_PART + ")?\\(\\s*(" + VARIABLE_PART + ")\\s*\\)\\s*\\{" +
          ".*?try\\{.*?\\}catch\\(\\s*(" + VARIABLE_PART + ")\\s*\\)\\s*\\{\\s*return[^}]*?\\+\\s*(?:\\1|\\2)[^}]*?\\}" +
          ".*?return[^}]*?\\};",
      Pattern.DOTALL
  );

  private final ConcurrentMap<String, SignatureCipher> cipherCache;
  private final Set<String> dumpedScriptUrls;
  private final ScriptEngine scriptEngine;
  private final Object cipherLoadLock;

  protected volatile CachedPlayerScript cachedPlayerScript;

  /**
   * Create a new signature cipher manager
   */
  public SignatureCipherManager() {
    this.cipherCache = new ConcurrentHashMap<>();
    this.dumpedScriptUrls = new HashSet<>();
    this.scriptEngine = new RhinoScriptEngineFactory().getScriptEngine();
    this.cipherLoadLock = new Object();
  }

  /**
   * Produces a valid playback URL for the specified track
   *
   * @param httpInterface HTTP interface to use
   * @param playerScript  Address of the script which is used to decipher signatures
   * @param format        The track for which to get the URL
   * @return Valid playback URL
   * @throws IOException On network IO error
   */
  @NotNull
  public URI resolveFormatUrl(@NotNull HttpInterface httpInterface,
                              @NotNull String playerScript,
                              @NotNull StreamFormat format) throws IOException {
    String signature = format.getSignature();
    String nParameter = format.getNParameter();
    URI initialUrl = format.getUrl();

    URIBuilder uri = new URIBuilder(initialUrl);
    SignatureCipher cipher = getCipherScript(httpInterface, playerScript);

    if (!DataFormatTools.isNullOrEmpty(signature)) {
      try {
        uri.setParameter(format.getSignatureKey(), cipher.apply(signature, scriptEngine));
      } catch (ScriptException | NoSuchMethodException e) {
        dumpProblematicScript(cipherCache.get(playerScript).rawScript, playerScript, "Can't transform s parameter " + signature);
        // Fallback: użyj oryginalnego signature aby zachować je w URL (diagnostyka, zgodnie z podejściem dla parametru n)
        try {
          uri.setParameter(format.getSignatureKey(), signature);
          log.debug("Falling back to original signature parameter (untransformed) for script {}", playerScript);
        } catch (Exception ignored) {
          // Brak lepszej opcji jeśli ustawienie również się nie uda.
        }
      }
    }
      

    if (!DataFormatTools.isNullOrEmpty(nParameter)) {
      String transformed = null;
      String primaryResult = null; // zapisz wynik pierwszej próby
      boolean primaryAttempted = false;
      boolean primaryFailed = false;
      try {
        transformed = cipher.transform(nParameter, scriptEngine);
        primaryAttempted = true;
        primaryResult = transformed;
        String logMessage = null;

        if (transformed == null) {
          logMessage = "Transformed n parameter is null, n function possibly faulty";
        } else if (nParameter.equals(transformed)) {
          logMessage = "Transformed n parameter is the same as input, n function possibly short-circuited";
        } else if (transformed.startsWith("enhanced_except_") || transformed.endsWith("_w8_" + nParameter)) {
          logMessage = "N function did not complete due to exception";
        }

        if (logMessage != null) {
            log.warn("{} (in: {}, out: {}, player script: {}, source version: {})",
                logMessage, nParameter, transformed, playerScript, YoutubeSource.VERSION);
        } else if (log.isDebugEnabled()) {
            log.debug("n parameter primary transform success (script: {}, in: {}, out: {})", playerScript, nParameter, transformed);
        }
      } catch (ScriptException | NoSuchMethodException e) {
        primaryFailed = true;
        dumpProblematicScript(cipherCache.get(playerScript).rawScript, playerScript, "Can't transform n parameter " + nParameter + " with " + cipher.nFunction + " n function");
        log.debug("Primary n transformation threw exception: {} - attempting NParamTransformer fallback", e.toString());
      }

      // Fallback lub poprawa jeśli primary dała wynik nieużyteczny
      boolean needFallback = primaryFailed || transformed == null || nParameter.equals(transformed) ||
          (transformed != null && (transformed.startsWith("enhanced_except_") || transformed.endsWith("_w8_" + nParameter)));

      if (needFallback) {
        try {
          NParamTransformer fallbackTransformer = new NParamTransformer(cipher.rawScript);
          String fallback = fallbackTransformer.transform(nParameter);
          if (fallback != null && !fallback.equals(nParameter) && !fallback.equals(transformed)) {
            log.info("n parameter improved via NParamTransformer fallback (in: {}, primary: {}, fallback: {})", nParameter, transformed, fallback);
            transformed = fallback;
          } else {
            log.debug("Fallback NParamTransformer didn't improve result (primaryFailed={}, primaryAttempted={}, resultPrimary={}, resultFallback={})", primaryFailed, primaryAttempted, transformed, fallback);
          }
        } catch (Exception fe) {
          log.debug("Fallback NParamTransformer failed: {}", fe.toString());
        }
      }

      // Log końcowy – zawsze wypisz finalny wynik (primary vs final) aby zobaczyć co trafia do URL
      if (log.isInfoEnabled()) {
        log.info("n parameter final (script: {}, original: {}, primary: {}, final: {})", playerScript, nParameter, primaryResult, transformed != null ? transformed : nParameter);
      }

      try {
        // Jeśli nadal null – zostaw oryginalny param n (throttling jest możliwy, ale URL będzie działał)
        uri.setParameter("n", transformed != null ? transformed : nParameter);
      } catch (Exception ignored) {
        try {
          uri.setParameter("n", nParameter);
        } catch (Exception ignored2) {
          // ostatecznie nic nie robimy
        }
      }
    }

    try {
      return uri.build(); // setParameter("ratebypass", "yes")  -- legacy parameter that will give 403 if tampered with.
    } catch (URISyntaxException e) {
      throw new RuntimeException(e);
    }
  }

  private CachedPlayerScript getPlayerScript(@NotNull HttpInterface httpInterface) {
    synchronized (cipherLoadLock) {
      try (CloseableHttpResponse response = httpInterface.execute(new HttpGet("https://www.youtube.com/embed/"))) {
        HttpClientTools.assertSuccessWithContent(response, "fetch player script (embed)");

        String responseText = EntityUtils.toString(response.getEntity());
        String scriptUrl = DataFormatTools.extractBetween(responseText, "\"jsUrl\":\"", "\"");

        if (scriptUrl == null) {
          throw throwWithDebugInfo(log, null, "no jsUrl found", "html", responseText);
        }

        return (cachedPlayerScript = new CachedPlayerScript(scriptUrl));
      } catch (IOException e) {
        throw ExceptionTools.toRuntimeException(e);
      }
    }
  }

  public CachedPlayerScript getCachedPlayerScript(@NotNull HttpInterface httpInterface) {
    if (cachedPlayerScript == null || System.currentTimeMillis() >= cachedPlayerScript.expireTimestampMs) {
      synchronized (cipherLoadLock) {
        if (cachedPlayerScript == null || System.currentTimeMillis() >= cachedPlayerScript.expireTimestampMs) {
          return getPlayerScript(httpInterface);
        }
      }
    }

    return cachedPlayerScript;
  }

  public SignatureCipher getCipherScript(@NotNull HttpInterface httpInterface,
                                         @NotNull String cipherScriptUrl) throws IOException {
    SignatureCipher cipherKey = cipherCache.get(cipherScriptUrl);

    if (cipherKey == null) {
      synchronized (cipherLoadLock) {
        log.debug("Parsing player script {}", cipherScriptUrl);

        try (CloseableHttpResponse response = httpInterface.execute(new HttpGet(parseTokenScriptUrl(cipherScriptUrl)))) {
          int statusCode = response.getStatusLine().getStatusCode();

          if (!HttpClientTools.isSuccessWithContent(statusCode)) {
            throw new IOException("Received non-success response code " + statusCode + " from script url " +
                cipherScriptUrl + " ( " + parseTokenScriptUrl(cipherScriptUrl) + " )");
          }

            String scriptBody = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
            try {
              cipherKey = extractFromScript(scriptBody, cipherScriptUrl);
            } catch (ScriptExtractionException e) {
              // Spróbuj fallbacków: jeśli konkretne nowe warianty mogłyby nie przejść, zaloguj rozszerzoną informację
              log.warn("Primary extraction failed ({}). Attempting relaxed patterns...", e.getFailureType());
              // (Na razie brak dodatkowych relaxed patterns – miejsce na przyszłe heurystyki)
              throw e;
            }
          cipherCache.put(cipherScriptUrl, cipherKey);
        }
      }
    }

    return cipherKey;
  }

  private List<String> getQuotedFunctions(@Nullable String... functionNames) {
    return Stream.of(functionNames)
        .filter(Objects::nonNull)
        .map(Pattern::quote)
        .collect(Collectors.toList());
  }

  private void dumpProblematicScript(@NotNull String script, @NotNull String sourceUrl,
                                     @NotNull String issue) {
    if (!dumpedScriptUrls.add(sourceUrl)) {
      return;
    }

    try {
      Path path = Files.createTempFile("lavaplayer-yt-player-script", ".js");
      Files.write(path, script.getBytes(StandardCharsets.UTF_8));

      log.error("Problematic YouTube player script {} detected (issue detected with script: {}). Dumped to {} (Source version: {})",
          sourceUrl, issue, path.toAbsolutePath(), YoutubeSource.VERSION);
    } catch (Exception e) {
      log.error("Failed to dump problematic YouTube player script {} (issue detected with script: {})", sourceUrl, issue);
    }
  }

  private SignatureCipher extractFromScript(@NotNull String script, @NotNull String sourceUrl) {
    Matcher scriptTimestamp = TIMESTAMP_PATTERN.matcher(script);

    if (!scriptTimestamp.find()) {
      scriptExtractionFailed(script, sourceUrl, ExtractionFailureType.TIMESTAMP_NOT_FOUND);
    }

    Matcher globalVarsMatcher = GLOBAL_VARS_PATTERN.matcher(script);

    if (!globalVarsMatcher.find()) {
      scriptExtractionFailed(script, sourceUrl, ExtractionFailureType.VARIABLES_NOT_FOUND);
    }

    Matcher sigActionsMatcher = ACTIONS_PATTERN.matcher(script);

    if (!sigActionsMatcher.find()) {
      scriptExtractionFailed(script, sourceUrl, ExtractionFailureType.SIG_ACTIONS_NOT_FOUND);
    }

    Matcher sigFunctionMatcher = SIG_FUNCTION_PATTERN.matcher(script);

    if (!sigFunctionMatcher.find()) {
      scriptExtractionFailed(script, sourceUrl, ExtractionFailureType.DECIPHER_FUNCTION_NOT_FOUND);
    }

    // Wybierz pierwszą funkcję, która nie jest identyczną (identity) – jeśli pierwsza była identity, szukaj dalej
    String sigFunction = null;
    sigFunctionMatcher.reset();
    while (sigFunctionMatcher.find()) {
      String candidate = sigFunctionMatcher.group(0);
      if (!isIdentitySigFunction(candidate)) {
        sigFunction = candidate;
        break;
      } else if (sigFunction == null) {
        // zachowaj pierwszą (identity) tylko gdy nic lepszego nie znajdziemy
        sigFunction = candidate;
      }
    }
    if (sigFunction == null) {
      scriptExtractionFailed(script, sourceUrl, ExtractionFailureType.DECIPHER_FUNCTION_NOT_FOUND);
    } else if (isIdentitySigFunction(sigFunction)) {
      log.debug("Selected decipher function appears identity (may cause unchanged signature) for script {}", sourceUrl);
    }

    Matcher nFunctionMatcher = N_FUNCTION_PATTERN.matcher(script);

    if (!nFunctionMatcher.find()) {
      Matcher fallbackNMatcher = N_FUNCTION_FALLBACK_PATTERN.matcher(script);
      if (fallbackNMatcher.find()) {
        nFunctionMatcher = fallbackNMatcher;
        log.debug("Using fallback N function pattern for script {}", sourceUrl);
      } else {
        scriptExtractionFailed(script, sourceUrl, ExtractionFailureType.N_FUNCTION_NOT_FOUND);
      }
    }

    String timestamp = scriptTimestamp.group(2);
    String globalVars = globalVarsMatcher.group("code");
    String sigActions = sigActionsMatcher.group(0);
    // sigFunction już wybrane powyżej
    String nFunction = nFunctionMatcher.group(0);

    String nfParameterName = DataFormatTools.extractBetween(nFunction, "(", ")");
    // Remove short-circuit that prevents n challenge transformation
    nFunction = nFunction.replaceAll("if\\s*\\(typeof\\s*[^\\s()]+\\s*===?.*?\\)return " + nfParameterName + "\\s*;?", "");

    return new SignatureCipher(timestamp, globalVars, sigActions, sigFunction, nFunction, script);
  }

  private void scriptExtractionFailed(String script, String sourceUrl, ExtractionFailureType failureType) {
    dumpProblematicScript(script, sourceUrl, "must find " + failureType.friendlyName);
    throw new ScriptExtractionException("Must find " + failureType.friendlyName + " from script: " + sourceUrl, failureType);
  }

  private static String extractDollarEscapedFirstGroup(@NotNull Pattern pattern, @NotNull String text) {
    Matcher matcher = pattern.matcher(text);
    return matcher.find() ? matcher.group(1).replace("$", "\\$") : null;
  }

  private static URI parseTokenScriptUrl(@NotNull String urlString) {
    try {
      if (urlString.startsWith("//")) {
        return new URI("https:" + urlString);
      } else if (urlString.startsWith("/")) {
        return new URI("https://www.youtube.com" + urlString);
      } else {
        return new URI(urlString);
      }
    } catch (URISyntaxException e) {
      throw new RuntimeException(e);
    }
  }

  public static class CachedPlayerScript {
    public final String url;
    public final long expireTimestampMs;

    protected CachedPlayerScript(@NotNull String url) {
      this.url = url;
      this.expireTimestampMs = System.currentTimeMillis() + TimeUnit.DAYS.toMillis(1);
    }
  }

  private boolean isIdentitySigFunction(String fnSource) {
    if (fnSource == null) return true;
    int paren = fnSource.indexOf('(');
    if (paren < 0) return false;
    int close = fnSource.indexOf(')', paren + 1);
    if (close < 0) return false;
    String params = fnSource.substring(paren + 1, close).trim();
    if (params.isEmpty()) return false;
    String firstParam = params.split(",")[0].trim();
    // Jeżeli zawiera split/join lub przypisanie do param – nie jest identity
    if (fnSource.contains(firstParam + "=") || fnSource.contains(".split(\"\")") || fnSource.contains(".reverse(")) return false;
    // Szukamy prostego return param;
    Pattern simpleReturn = Pattern.compile("return\\s+" + Pattern.quote(firstParam) + "\\s*;?");
    Matcher m = simpleReturn.matcher(fnSource);
    return m.find();
  }
}
