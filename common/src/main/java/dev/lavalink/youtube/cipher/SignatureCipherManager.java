package dev.lavalink.youtube.cipher;

import com.sedmelluq.discord.lavaplayer.tools.DataFormatTools;
import com.sedmelluq.discord.lavaplayer.tools.io.HttpInterface;
import dev.lavalink.youtube.track.format.StreamFormat;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.util.EntityUtils;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import javax.net.ssl.HttpsURLConnection;
import java.net.HttpURLConnection;
import java.net.URL;
import java.io.OutputStream;
import java.io.InputStream;
import java.net.URLConnection;

/**
 * Handles parsing and caching of signature ciphers via external cipher endpoint
 */
public class SignatureCipherManager {
    private static final Logger log = LoggerFactory.getLogger(SignatureCipherManager.class);
    private final String cipherEndpoint;
    private final String bearerToken;

    /**
     * @param cipherEndpoint URL endpoint for signature decoding (e.g. http://localhost:8001/decrypt_signature)
     * @param bearerToken Bearer token for authorization
     */
    public SignatureCipherManager(@NotNull String cipherEndpoint, @NotNull String bearerToken) {
        this.cipherEndpoint = Objects.requireNonNull(cipherEndpoint);
        this.bearerToken = Objects.requireNonNull(bearerToken);
    }

    /**
     * Produces a valid playback URL for the specified track using external cipher endpoint
     *
     * @param httpInterface HTTP interface to use (not used, kept for compatibility)
     * @param playerScript  Address of the script which is used to decipher signatures
     * @param format        The track for which to get the URL
     * @param videoId       The YouTube video ID
     * @return Valid playback URL
     * @throws IOException On network IO error
     */
    @NotNull
    public URI resolveFormatUrl(@NotNull HttpInterface httpInterface,
                                @NotNull String playerScript,
                                @NotNull StreamFormat format,
                                @NotNull String videoId) throws IOException {
        String signature = format.getSignature();
        String nParameter = format.getNParameter();
        URI initialUrl = format.getUrl();
        URIBuilder uri = new URIBuilder(initialUrl);

        if (!DataFormatTools.isNullOrEmpty(signature) || !DataFormatTools.isNullOrEmpty(nParameter)) {
            // Prepare JSON body
            String jsonBody = "{" +
                    (signature != null ? "\"encrypted_signature\":\"" + escapeJson(signature) + "\"," : "") +
                    (nParameter != null ? "\"n_param\":\"" + escapeJson(nParameter) + "\"," : "") +
                    "\"player_url\":\"" + escapeJson(playerScript) + "\"," +
                    "\"video_id\":\"" + escapeJson(videoId) + "\"}";

            // Send POST to cipherEndpoint
            URL url = new URL(cipherEndpoint);
            URLConnection urlConnection = url.openConnection();
            if (urlConnection instanceof HttpsURLConnection) {
                HttpsURLConnection conn = (HttpsURLConnection) urlConnection;
                conn.setRequestMethod("POST");
                conn.setRequestProperty("Content-Type", "application/json");
                conn.setRequestProperty("Authorization", "Bearer " + bearerToken);
                conn.setDoOutput(true);
                try (OutputStream os = conn.getOutputStream()) {
                    os.write(jsonBody.getBytes(StandardCharsets.UTF_8));
                }
                int responseCode = conn.getResponseCode();
                if (responseCode != 200) {
                    String errorMsg = "Cipher endpoint returned HTTP " + responseCode + ": " + readStream(conn.getErrorStream());
                    log.error(errorMsg);
                    throw new IOException(errorMsg);
                }
                String response = readStream(conn.getInputStream());
                // Expected JSON: { "decrypted_signature": "...", "decrypted_n_sig": "..." }
                String decryptedSignature = extractJsonField(response, "decrypted_signature");
                String decryptedN = extractJsonField(response, "decrypted_n_sig");

                if (!DataFormatTools.isNullOrEmpty(signature) && decryptedSignature != null) {
                    uri.setParameter(format.getSignatureKey(), decryptedSignature);
                }
                if (!DataFormatTools.isNullOrEmpty(nParameter) && decryptedN != null) {
                    uri.setParameter("n", decryptedN);
                }
            } else if (urlConnection instanceof HttpURLConnection) {
                HttpURLConnection conn = (HttpURLConnection) urlConnection;
                conn.setRequestMethod("POST");
                conn.setRequestProperty("Content-Type", "application/json");
                conn.setRequestProperty("Authorization", "Bearer " + bearerToken);
                conn.setDoOutput(true);
                try (OutputStream os = conn.getOutputStream()) {
                    os.write(jsonBody.getBytes(StandardCharsets.UTF_8));
                }
                int responseCode = conn.getResponseCode();
                if (responseCode != 200) {
                    String errorMsg = "Cipher endpoint returned HTTP " + responseCode + ": " + readStream(conn.getErrorStream());
                    log.error(errorMsg);
                    throw new IOException(errorMsg);
                }
                String response = readStream(conn.getInputStream());
                // Expected JSON: { "decrypted_signature": "...", "decrypted_n_sig": "..." }
                String decryptedSignature = extractJsonField(response, "decrypted_signature");
                String decryptedN = extractJsonField(response, "decrypted_n_sig");

                if (!DataFormatTools.isNullOrEmpty(signature) && decryptedSignature != null) {
                    uri.setParameter(format.getSignatureKey(), decryptedSignature);
                }
                if (!DataFormatTools.isNullOrEmpty(nParameter) && decryptedN != null) {
                    uri.setParameter("n", decryptedN);
                }
            } else {
                throw new IOException("Unsupported URL connection type: " + urlConnection.getClass());
            }
        }
        try {
            return uri.build();
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }
    }

    // Helper method to extract a field from simple JSON (without a parser)
    private static String extractJsonField(String json, String field) {
        String pattern = "\\\"" + field + "\\\":\\\"([^\\\"]*)\\\"";
        java.util.regex.Matcher m = java.util.regex.Pattern.compile(pattern).matcher(json);
        return m.find() ? m.group(1) : null;
    }

    // Helper method to read a stream
    private static String readStream(InputStream is) throws IOException {
        if (is == null) return "";
        try (java.util.Scanner s = new java.util.Scanner(is, "UTF-8").useDelimiter("\\A")) {
            return s.hasNext() ? s.next() : "";
        }
    }

    // Helper method to escape JSON characters
    private static String escapeJson(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
