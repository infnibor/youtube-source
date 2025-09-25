package dev.lavalink.youtube.cipher;

import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Fetches the latest YouTube player script URL from the YouTube homepage.
 * Simple cache to avoid excessive requests.
 */
public class LatestPlayerUrlFetcher {
    private static final Logger log = LoggerFactory.getLogger(LatestPlayerUrlFetcher.class);
    private static final String YOUTUBE_URL = "https://www.youtube.com";
    private static final Pattern PLAYER_JS_PATTERN = Pattern.compile("\\\"jsUrl\\\":\\\"(/s/player/[^\"]+?base\\.js)\\\"");
    private static final long CACHE_DURATION_MS = 60 * 60 * 1000; // 1h

    private String cachedPlayerUrl = null;
    private long cacheTimestamp = 0;

    /**
     * Fetches the latest player URL from YouTube, using cache if not expired.
     * @return Absolute URL to the latest player script
     * @throws IOException On network error
     */
    public synchronized @NotNull String fetchLatestPlayerUrl() throws IOException {
        long now = System.currentTimeMillis();
        if (cachedPlayerUrl != null && (now - cacheTimestamp) < CACHE_DURATION_MS) {
            return cachedPlayerUrl;
        }
        String homepage = fetchUrl(YOUTUBE_URL);
        Matcher matcher = PLAYER_JS_PATTERN.matcher(homepage);
        if (matcher.find()) {
            String jsPath = matcher.group(1);
            String playerUrl = YOUTUBE_URL + jsPath;
            cachedPlayerUrl = playerUrl;
            cacheTimestamp = now;
            log.info("Fetched latest player URL: {}", playerUrl);
            return playerUrl;
        } else {
            throw new IOException("Could not find player.js URL in YouTube homepage");
        }
    }

    private String fetchUrl(String url) throws IOException {
        HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
        conn.setRequestProperty("User-Agent", "Mozilla/5.0");
        conn.setConnectTimeout(5000);
        conn.setReadTimeout(5000);
        try (InputStream is = conn.getInputStream()) {
            return new String(is.readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}
