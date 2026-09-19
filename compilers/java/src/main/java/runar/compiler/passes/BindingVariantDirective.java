package runar.compiler.passes;

import java.util.Set;
import java.util.regex.Pattern;

/**
 * {@code @bindingVariant} directive parsing — Java port of
 * {@code packages/runar-compiler/src/passes/bindingvariant-directive.ts}
 * (and the Go {@code frontend/bindingvariant_directive.go}).
 *
 * <p>A public method may carry a {@code /** @bindingVariant <VARIANT> *&#47;}
 * comment directive selecting which Any-S OP_PUSH_TX preimage-binding
 * construction its auto-injected covenant emits: {@code "lowS"} (default; low-S
 * fixup, safe under the LOW_S rule that applies to nVersion = 1) or {@code
 * "all"} (compact non-low-S, ~45 bytes smaller, valid only for spends with
 * nVersion != 1).
 *
 * <p>The default (no directive) is {@code "lowS"} — byte-identical to the
 * historically-pinned binding blob, so existing fixtures see ZERO change.
 * Detection lives in the parser; this class owns the variant grammar.
 */
public final class BindingVariantDirective {
    private BindingVariantDirective() {}

    /** The construction used when no directive is present. */
    public static final String DEFAULT = "lowS";

    /** The recognised variant names (as written). Case-sensitive. */
    private static final Set<String> VALUES = Set.of("lowS", "all");

    /** Parse result: exactly one of {@code value} / {@code error} is non-null. */
    public record Result(String value, String error) {
        static Result ok(String v) { return new Result(v, null); }
        static Result err(String e) { return new Result(null, e); }
        public boolean isError() { return error != null; }
    }

    /**
     * Parse the value text of a {@code @bindingVariant} directive.
     *
     * <p>Case-sensitive: only {@code "lowS"} and {@code "all"} are accepted, so a
     * typo is rejected rather than silently defaulted (a mis-declared binding is
     * an exploit class).
     */
    public static Result parseBindingVariant(String variantText) {
        String raw = variantText == null ? "" : variantText.trim();
        if (raw.isEmpty()) {
            return Result.err(
                "@bindingVariant directive requires a value "
                + "(`@bindingVariant all` or `@bindingVariant lowS`)");
        }
        if (!VALUES.contains(raw)) {
            return Result.err(
                "@bindingVariant: unknown variant \"" + raw + "\" (valid: lowS, all)");
        }
        return Result.ok(raw);
    }

    private static final Pattern BINDING_VARIANT_TOKEN =
        Pattern.compile("@bindingVariant\\b");
    private static final String LINE_START_ERR =
        "@bindingVariant must be a JSDoc tag at the start of a comment line "
        + "(`@bindingVariant all` or `@bindingVariant lowS`)";

    private static boolean isIdentChar(char c) {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_';
    }

    private static String stripCommentLine(String raw) {
        String s = raw.replaceFirst("^[ \\t]+", "");
        if (s.startsWith("//")) s = s.substring(2).replaceFirst("^[ \\t]+", "");
        else if (s.startsWith("/**")) s = s.substring(3).replaceFirst("^[ \\t]+", "");
        else if (s.startsWith("/*")) s = s.substring(2).replaceFirst("^[ \\t]+", "");
        else if (s.startsWith("*")) s = s.substring(1).replaceFirst("^[ \\t]+", "");
        s = s.replaceFirst("[ \\t]+$", "");
        if (s.endsWith("*/")) s = s.substring(0, s.length() - 2).replaceFirst("[ \\t]+$", "");
        return s;
    }

    /**
     * Extract and parse a {@code @bindingVariant} directive from a block of
     * comment text. Returns {@code null} when no {@code @bindingVariant} token is
     * present, otherwise the parse result (value or error). Only a JSDoc/line
     * tag at the start of a comment line is a directive.
     */
    public static Result extractBindingVariantDirective(String commentText) {
        if (commentText == null || !BINDING_VARIANT_TOKEN.matcher(commentText).find()) {
            return null;
        }
        for (String raw : commentText.split("\\R", -1)) {
            String line = stripCommentLine(raw);
            if (!line.startsWith("@bindingVariant")) continue;
            String rest = line.substring("@bindingVariant".length());
            if (!rest.isEmpty() && isIdentChar(rest.charAt(0))) continue;
            if (!rest.isEmpty() && rest.charAt(0) != ' ' && rest.charAt(0) != '\t') {
                return Result.err(LINE_START_ERR);
            }
            return parseBindingVariant(rest.trim());
        }
        return Result.err(LINE_START_ERR);
    }
}
