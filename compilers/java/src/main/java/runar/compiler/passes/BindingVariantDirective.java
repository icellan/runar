package runar.compiler.passes;

import java.util.regex.Pattern;

/**
 * {@code @bindingVariant} directive parsing (ports #170; original design:
 * brendan-elas, #167). Mirrors
 * packages/runar-compiler/src/passes/bindingvariant-directive.ts; diagnostic
 * text is identical in all seven tiers.
 *
 * <p>A public {@code .runar.ts} method may carry
 * {@code /** @bindingVariant <lowS|all> *&#47;}, selecting the Any-S OP_PUSH_TX
 * binding construction its checkPreimage emits. {@code lowS} (default) is valid
 * at every tx nVersion; {@code all} is the compact non-low-S blob, spendable
 * only when the spending tx has nVersion > 1. Same marker rules as
 * {@code @sighash} (F-039 / N-039): one marker per method, and anything other
 * than {@code " lowS"} / {@code " all"} after it is an error.
 */
public final class BindingVariantDirective {

    private BindingVariantDirective() {}

    public static final String MARKER = "@bindingVariant";

    public static final String MALFORMED_ERROR =
        "@bindingVariant: malformed directive; expected `@bindingVariant lowS` or `@bindingVariant all`";
    public static final String MULTIPLE_ERROR =
        "@bindingVariant: more than one @bindingVariant directive on this method; declare exactly one";

    private static final Pattern SEGMENT = Pattern.compile("[ \\t][A-Za-z0-9_ \\t]*");

    /** Either a variant ({@code "lowS"} / {@code "all"}) or an error message. */
    public record Result(String value, String error) {
        public boolean isError() {
            return error != null;
        }
    }

    static Result parseBindingVariant(String text) {
        String raw = text.replaceAll("^[ \\t]+|[ \\t]+$", "");
        if (raw.equals("lowS") || raw.equals("all")) return new Result(raw, null);
        if (raw.isEmpty()) return new Result(null, MALFORMED_ERROR);
        return new Result(null, "@bindingVariant: unknown variant \"" + raw + "\" (valid: lowS, all)");
    }

    /**
     * Extract and parse a {@code @bindingVariant} directive from a method's
     * leading-comment text. {@code null} only when no marker occurs.
     */
    public static Result extract(String commentText) {
        if (commentText == null) return null;
        int first = commentText.indexOf(MARKER);
        if (first == -1) return null;
        String after = commentText.substring(first + MARKER.length());
        if (after.contains(MARKER)) return new Result(null, MULTIPLE_ERROR);
        int end = after.length();
        for (int i = 0; i < after.length(); i++) {
            char c = after.charAt(i);
            if (c == '\n' || c == '\r' || (c == '*' && i + 1 < after.length() && after.charAt(i + 1) == '/')) {
                end = i;
                break;
            }
        }
        String seg = after.substring(0, end);
        if (!SEGMENT.matcher(seg).matches()) return new Result(null, MALFORMED_ERROR);
        return parseBindingVariant(seg);
    }

    /** The non-TS surfaces' refusal, identical in all seven tiers. */
    public static String unsupportedMessage(String surfaceName) {
        return "@bindingVariant directive is not supported by the " + surfaceName
            + " surface parser; write the contract in TypeScript (.runar.ts), where @bindingVariant is honoured";
    }
}
