package dev.lavalink.youtube.cipher;

import javax.script.Invocable;
import javax.script.ScriptEngine;
import javax.script.ScriptException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.mozilla.javascript.engine.RhinoScriptEngineFactory;

/**
 * Helper do parsowania i transformacji funkcji "n" z player scriptu YouTube.
 * Używa Rhino (Nashorn usunięty w nowszych wersjach JDK).
 * Ten fallback jest bardziej liberalny niż główne wyrażenia w SignatureCipherManager.
 */
public class NParamTransformer {

    private static final Pattern N_FUNCTION_HEADER = Pattern.compile(
            "(?i)\\bN\\s*:\\s*function\\s*\\(([^)]*)\\)\\s*\\{", Pattern.DOTALL);

    private final String wrappedFunctionSource;
    private final boolean hasParam; // czy oryginalna funkcja ma (przynajmniej jeden) parametr

    public NParamTransformer(String playerScript) {
        Matcher m = N_FUNCTION_HEADER.matcher(playerScript);
        if (!m.find()) {
            throw new IllegalStateException(
                    "Could not locate n function (property form N: function(...) { ... }) in player script");
        }

        int bodyStart = m.end();
        int idx = bodyStart;
        int depth = 1;
        char[] chars = playerScript.toCharArray();
        final int len = chars.length;
        boolean inString = false;
        char stringQuote = '\0';
        boolean escape = false;
        boolean inRegex = false;
        boolean inSingleLineComment = false;
        boolean inMultiLineComment = false;

        while (idx < len && depth > 0) {
            char c = chars[idx];
            if (inSingleLineComment) {
                if (c == '\n' || c == '\r') inSingleLineComment = false;
                idx++; continue;
            }
            if (inMultiLineComment) {
                if (c == '*' && idx + 1 < len && chars[idx + 1] == '/') { inMultiLineComment = false; idx += 2; continue; }
                idx++; continue;
            }
            if (inString) {
                if (escape) { escape = false; idx++; continue; }
                if (c == '\\') { escape = true; idx++; continue; }
                if (c == stringQuote) inString = false;
                idx++; continue;
            }
            if (inRegex) {
                if (escape) { escape = false; idx++; continue; }
                if (c == '\\') { escape = true; idx++; continue; }
                if (c == '/') inRegex = false;
                idx++; continue;
            }
            if (c == '/') {
                if (idx + 1 < len) {
                    char n = chars[idx + 1];
                    if (n == '/') { inSingleLineComment = true; idx += 2; continue; }
                    if (n == '*') { inMultiLineComment = true; idx += 2; continue; }
                }
            }
            if (c == '\'' || c == '"' || c == '`') { inString = true; stringQuote = c; idx++; continue; }
            if (c == '/' && idx + 1 < len) {
                char n = chars[idx + 1];
                if (n != '/' && n != '*') { inRegex = true; idx++; continue; }
            }
            if (c == '{') depth++;
            else if (c == '}') depth--;
            idx++;
        }

        if (depth != 0) {
            throw new IllegalStateException("Unterminated n function body while parsing player script");
        }

        int bodyEnd = idx - 1;
        String body = playerScript.substring(bodyStart, bodyEnd);

        String paramList = m.group(1).trim();
        String firstParam = null;
        if (!paramList.isEmpty()) {
            int comma = paramList.indexOf(',');
            firstParam = (comma >= 0 ? paramList.substring(0, comma) : paramList).trim();
            if (firstParam.isEmpty()) firstParam = null;
        }
        this.hasParam = firstParam != null;

        // Budowanie funkcji transformującej dla Rhino
        StringBuilder sb = new StringBuilder();
        sb.append("function nTransform(a){");
        if (hasParam) {
            sb.append("var ").append(firstParam).append("=a;");
        }
        sb.append(body);
        sb.append('}');
        this.wrappedFunctionSource = sb.toString();
    }

    private ScriptEngine newEngine() {
        return new RhinoScriptEngineFactory().getScriptEngine();
    }

    /**
     * Transformuje wartość parametru n.
     * Jeśli funkcja nie ma parametrów lub zwraca input bez zmian,
     * traktujemy jako brak transformacji i zwracamy wejście.
     */
    public String transform(String input) throws ScriptException, NoSuchMethodException {
        if (!hasParam) {
            return input; // brak transformacji
        }
        ScriptEngine engine = newEngine();
        engine.eval(wrappedFunctionSource);
        Object result = ((Invocable) engine).invokeFunction("nTransform", input);
        if (result == null || result.toString().equals(input)) {
            // YouTube już nie transformuje n – traktujemy jako poprawne
            return input;
        }
        return result.toString();
    }
}
