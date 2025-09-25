package dev.lavalink.youtube.cipher;

import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.script.Invocable;
import javax.script.ScriptEngine;
import javax.script.ScriptException;

import org.mozilla.javascript.engine.RhinoScriptEngineFactory;

/**
 * Describes one signature cipher
 */
public class SignatureCipher {
    private static final Logger log = LoggerFactory.getLogger(SignatureCipher.class);

    public final String timestamp;
    public final String globalVars;
    public final String sigActions;
    public final String sigFunction;
    public final String nFunction;
    public final String rawScript;

    public SignatureCipher(@NotNull String timestamp,
                           @NotNull String globalVars,
                           @NotNull String sigActions,
                           @NotNull String sigFunction,
                           @NotNull String nFunction,
                           @NotNull String rawScript) {
        this.timestamp = timestamp;
        this.globalVars = globalVars;
        this.sigActions = sigActions;
        this.sigFunction = sigFunction;
        this.nFunction = nFunction;
        this.rawScript = rawScript;
    }

    /**
     * Use a fresh ScriptEngine for each invocation to avoid state leakage between different scripts
     * or between signature and n-function evaluation. Some player scripts rely on global state or
     * create different objects that collide when the same engine instance is reused.
     */
    private ScriptEngine newEngine() {
        return new RhinoScriptEngineFactory().getScriptEngine();
    }
//  /**
//   * @param text Text to apply the cipher on
//   * @return The result of the cipher on the input text
//   */
//  public String apply(@NotNull String text) {
//    StringBuilder builder = new StringBuilder(text);
//
//    for (CipherOperation operation : operations) {
//      switch (operation.type) {
//        case SWAP:
//          int position = operation.parameter % text.length();
//          char temp = builder.charAt(0);
//          builder.setCharAt(0, builder.charAt(position));
//          builder.setCharAt(position, temp);
//          break;
//        case REVERSE:
//          builder.reverse();
//          break;
//        case SLICE:
//        case SPLICE:
//          builder.delete(0, operation.parameter);
//          break;
//        default:
//          throw new IllegalStateException("All branches should be covered");
//      }
//    }
//
//    return builder.toString();
//  }
    /**
     * Apply the signature decryption function.
     * @param text Text to apply the cipher on
     * @param _ignored A ScriptEngine parameter (ignored) – a fresh engine is created internally to avoid state leakage
     * @return The result of the cipher on the input text
     */
    public String apply(@NotNull String text,
                        @NotNull ScriptEngine _ignored) throws ScriptException, NoSuchMethodException {
        // ignore passed engine; use a fresh one to keep execution isolated
        ScriptEngine engine = newEngine();
        Object result;

        engine.eval(globalVars + ";" + sigActions + ";decrypt_sig=" + sigFunction);
        try {
            result = ((Invocable) engine).invokeFunction("decrypt_sig", text);
        } catch (NoSuchMethodException e) {
            // Re-throw to allow caller to handle dumping or fallback
            throw e;
        }

        return result == null ? null : String.valueOf(result);
    }

    /**
     * Transform the n parameter using the extracted n function.
     * @param text Text to transform
     * @param _ignored A ScriptEngine parameter (ignored) – a fresh engine is created internally to avoid state leakage
     * @return The result of the n parameter transformation
     */
    public String transform(@NotNull String text, @NotNull ScriptEngine _ignored)
            throws ScriptException, NoSuchMethodException {
        ScriptEngine engine = newEngine();
        Object result;

        // Many n functions reuse objects from sigActions; load both.
        engine.eval(globalVars + ";" + sigActions + ";decrypt_nsig=" + nFunction);
        try {
            result = ((Invocable) engine).invokeFunction("decrypt_nsig", text);
        } catch (NoSuchMethodException e) {
            throw e;
        }

        String transformed = result == null ? null : String.valueOf(result);

        if (text.equals(transformed)) {
            // Attempt sanitization: remove early-return identity guards and try again on a fresh engine
            String paramName = extractFirstParameterName(nFunction);
            if (paramName != null) {
                String sanitized = nFunction;
                // Remove simple "if (...) return <param>;" (various spaces, optional semicolon)
                sanitized = sanitized.replaceAll("if\\s*\\([^{}]*?\\)\\s*return\\s+" + paramName + "\\s*;?", "");
                // Remove lone 'return <param>;' occurrences that may short-circuit
                sanitized = sanitized.replaceAll("return\\s+" + paramName + "\\s*;?", "");

                if (!sanitized.equals(nFunction)) {
                    try {
                        ScriptEngine engine2 = newEngine();
                        engine2.eval(globalVars + ";" + sigActions + ";decrypt_nsig=" + sanitized);
                        Object retryObj = ((Invocable) engine2).invokeFunction("decrypt_nsig", text);
                        String retry = retryObj == null ? null : String.valueOf(retryObj);
                        if (retry != null && !text.equals(retry)) {
                            log.debug("n parameter transformed after sanitizing early returns (in: {}, out: {})", text, retry);
                            transformed = retry;
                        } else {
                            log.debug("Sanitized n function still returns original input (param: {})", paramName);
                        }
                    } catch (Exception e) {
                        log.debug("Retry transform with sanitized n function failed: {}", e.getMessage());
                    }
                }
            }

            if (text.equals(transformed)) {
                String preview = nFunction.length() > 400 ? nFunction.substring(0, 400) + "..." : nFunction;
                log.warn("n function produced identity result; extracted nFunction preview: {}", preview.replace('\n',' '));
            }
        }

        return transformed;
    }
    //  /**
//   * @param operation The operation to add to this cipher
//   */
//  public void addOperation(@NotNull CipherOperation operation) {
//    operations.add(operation);
//  }
//
//  /**
//   * @return True if the cipher contains no operations.
//   */
//  public boolean isEmpty() {
//    return operations.isEmpty();
//  }
    private String extractFirstParameterName(String functionSource) {
        int start = functionSource.indexOf('(');
        if (start < 0) return null;
        int end = functionSource.indexOf(')', start + 1);
        if (end < 0) return null;
        String inside = functionSource.substring(start + 1, end).trim();
        if (inside.isEmpty()) return null;
        int comma = inside.indexOf(',');
        if (comma > 0) inside = inside.substring(0, comma).trim();
        return inside.isEmpty() ? null : inside;
    }
}
