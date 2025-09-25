import dev.lavalink.youtube.cipher.SignatureCipherManager;
import org.junit.jupiter.api.Test;
import java.io.IOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Scanner;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

public class SigFunctionPatternTest {
    private static final String SCRIPT_URL = "https://www.youtube.com/s/player/377ca75b/player_ias.vflset/pl_PL/base.js";

    @Test
    public void testSigFunctionPatternOnLatestScript() throws IOException {
        String script = fetchScript(SCRIPT_URL);
        Pattern sigFunctionPattern = getSigFunctionPattern();
        Matcher matcher = sigFunctionPattern.matcher(script);
        boolean matched = matcher.find();
        System.out.println("Latest YouTube player script URL: " + SCRIPT_URL);
        if (matched) {
            System.out.println("SIG_FUNCTION_PATTERN: Passed");
        } else {
            System.out.println("SIG_FUNCTION_PATTERN: Failed");
            // Szukamy podejrzanych funkcji z return i wywołaniem innej funkcji
            Pattern candidatePattern = Pattern.compile(
                "function\\s*\\(\\s*\\w+\\s*\\)\\s*\\{[^}]*?return\\s*\\w+\\s*\\([^}]{0,200}\\);?[^}]*?\\}",
                Pattern.DOTALL
            );
            Matcher candidateMatcher = candidatePattern.matcher(script);
            int count = 0;
            while (candidateMatcher.find() && count < 5) { // pokaż max 5
                String candidate = candidateMatcher.group();
                System.out.println("Possible signature function candidate:\n" + candidate + "\n---");
                count++;
            }
            if (count == 0) {
                System.out.println("No candidate functions found. Regex may require szerszy wzorzec.");
            }
        }
    }

    private String fetchScript(String url) throws IOException {
        StringBuilder sb = new StringBuilder();
        try (java.io.InputStream is = new URL(url).openStream();
             java.io.Reader reader = new java.io.InputStreamReader(is, StandardCharsets.UTF_8)) {
            char[] buf = new char[8192];
            int len;
            while ((len = reader.read(buf)) != -1) {
                sb.append(buf, 0, len);
            }
        }
        return sb.toString();
    }

    private Pattern getSigFunctionPattern() {
        try {
            java.lang.reflect.Field field = SignatureCipherManager.class.getDeclaredField("SIG_FUNCTION_PATTERN");
            field.setAccessible(true);
            return (Pattern) field.get(null);
        } catch (Exception e) {
            throw new RuntimeException("Could not access SIG_FUNCTION_PATTERN", e);
        }
    }
};
