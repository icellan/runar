package runar.lang.sdk;

import java.nio.charset.StandardCharsets;

/**
 * 1sat ordinals inscription payload. Mirrors {@code Inscription} in the
 * Go / Rust / Python / Zig / Ruby SDKs.
 *
 * <p>Envelope layout when spliced into a locking script:
 * <pre>
 *   OP_FALSE OP_IF PUSH("ord") OP_1 PUSH(content-type) OP_0 PUSH(data) OP_ENDIF
 *   00       63   03 6f7264   51  &lt;push&gt;         00  &lt;push&gt;   68
 * </pre>
 *
 * <p>The envelope is a no-op at runtime (OP_FALSE skips the IF block)
 * and can be placed between the contract code and state sections
 * without affecting execution. {@link RunarContract#withInscription}
 * attaches one to a deployed locking script.
 */
public record Inscription(String contentType, String data) {

    /**
     * Builds the ordinals envelope hex for this inscription.
     */
    public String toEnvelopeHex() {
        return buildEnvelope(contentType, data);
    }

    /**
     * Builds a 1sat ordinals envelope from the given content type and
     * hex-encoded data payload. The {@code data} argument is already
     * hex — callers that have raw bytes should hex-encode first.
     */
    public static String buildEnvelope(String contentType, String dataHex) {
        byte[] ctBytes = contentType.getBytes(StandardCharsets.UTF_8);
        String ctHex = ScriptUtils.bytesToHex(ctBytes);
        StringBuilder sb = new StringBuilder();
        // OP_FALSE (00) OP_IF (63) PUSH3 "ord" (03 6f7264) OP_1 (51)
        sb.append("00").append("63").append("03").append("6f7264").append("51");
        sb.append(ScriptUtils.encodePushData(ctHex));
        sb.append("00"); // OP_0 — content delimiter
        sb.append(ScriptUtils.encodePushData(dataHex));
        sb.append("68"); // OP_ENDIF
        return sb.toString();
    }
}
