package dev.lavalink.youtube.cipher;

import org.junit.jupiter.api.Test;
import org.mozilla.javascript.engine.RhinoScriptEngineFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.script.ScriptEngine;

import static org.junit.jupiter.api.Assertions.assertEquals;

class SignatureCipherTest {
    private static final Logger log = LoggerFactory.getLogger(SignatureCipherTest.class);

    @Test
    void testTransformNWithAbObject() {
        // Dodajemy obiekt Ab do globalVars
        String globalVars = "var Ab={a:function(x){return x+1;},b:function(y){return y-1;},c:function(z){return z*2;}};";
        // Wymuszamy zwracanie stringa
        String nFunction = "function(l){return String(Ab.a(parseInt(l)));}";
        String rawScript = "";
        SignatureCipher cipher = new SignatureCipher("timestamp", globalVars, "", "", nFunction, rawScript);
        ScriptEngine engine = new RhinoScriptEngineFactory().getScriptEngine();
        String input = "41";
        try {
            String result = cipher.transform(input, engine);
            // Oczekujemy, że Ab.a(41) = 42
            assertEquals("42", result);
            log.info("Transform result with Ab: {}", result);
        } catch (javax.script.ScriptException | NoSuchMethodException e) {
            throw new RuntimeException(e);
        }
    }
}
