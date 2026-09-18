package runar.compiler.passes;

import java.util.Set;
import java.util.regex.Matcher;
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

    /**
     * Extract the value following an {@code @bindingVariant} token in a block of
     * comment text. Mirrors the TS {@code BINDING_VARIANT_RE}.
     */
    private static final Pattern BINDING_VARIANT_RE =
        Pattern.compile("@bindingVariant\\s+([A-Za-z0-9_]*?)(?:\\*/|\\n|\\r|\\s|$)");

    /**
     * Extract and parse a {@code @bindingVariant} directive from a block of
     * comment text. Returns {@code null} when no {@code @bindingVariant} token is
     * present, otherwise the parse result (value or error).
     */
    public static Result extractBindingVariantDirective(String commentText) {
        if (commentText == null) {
            return null;
        }
        Matcher m = BINDING_VARIANT_RE.matcher(commentText);
        if (!m.find()) {
            return null;
        }
        return parseBindingVariant(m.group(1) == null ? "" : m.group(1));
    }
}
