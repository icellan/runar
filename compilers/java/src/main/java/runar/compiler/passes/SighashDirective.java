package runar.compiler.passes;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/**
 * {@code @sighash} directive parsing (issue #123) — Java port of
 * {@code packages/runar-compiler/src/passes/sighash-directive.ts}.
 *
 * <p>A public method may carry a {@code /** @sighash <FLAGS> *&#47;} comment
 * directive that declares which BIP-143 sighash type its auto-injected covenant
 * (and the SDK-built preimage) commits to. {@code <FLAGS>} is a {@code |}-separated
 * set of SigHash names, e.g. {@code SINGLE|FORKID}, {@code ALL|ANYONECANPAY|FORKID},
 * {@code NONE|FORKID}.
 *
 * <p>The default (no directive) is {@code ALL|FORKID} (0x41) — byte-identical to
 * the historically-pinned mode, so existing fixtures see ZERO change. Detection
 * lives in the parser; this class owns the flag grammar (name -&gt; value, combo
 * validity, FORKID-mandatory).
 */
public final class SighashDirective {
    private SighashDirective() {}

    /** Numeric value of each sighash flag name. */
    private static final Map<String, Integer> FLAG_VALUES = new LinkedHashMap<>();
    static {
        FLAG_VALUES.put("ALL", 0x01);
        FLAG_VALUES.put("NONE", 0x02);
        FLAG_VALUES.put("SINGLE", 0x03);
        FLAG_VALUES.put("FORKID", 0x40);
        FLAG_VALUES.put("ANYONECANPAY", 0x80);
    }

    /** The base-type names. Exactly one MUST appear in a directive. */
    private static final Set<String> BASE_TYPE_NAMES = Set.of("ALL", "NONE", "SINGLE");

    /** SIGHASH_ALL | SIGHASH_FORKID — the default when no directive is present. */
    public static final int SIGHASH_DEFAULT = 0x41;

    /**
     * Base-type mask. {@code sigHashType & BASE_TYPE_MASK} recovers 1/2/3
     * (ALL/NONE/SINGLE) after the FORKID/ANYONECANPAY high bits are stripped.
     */
    public static final int BASE_TYPE_MASK = 0x1f;
    public static final int BASE_ALL = 0x01;
    public static final int BASE_NONE = 0x02;
    public static final int BASE_SINGLE = 0x03;
    public static final int FLAG_FORKID = 0x40;
    public static final int FLAG_ANYONECANPAY = 0x80;

    /** Parse result: exactly one of {@code value} / {@code error} is non-null. */
    public record Result(Integer value, String error) {
        static Result ok(int v) { return new Result(v, null); }
        static Result err(String e) { return new Result(null, e); }
        public boolean isError() { return error != null; }
    }

    /**
     * Parse the flag list of an {@code @sighash} directive.
     *
     * <p>{@code flagsText} is the raw text following {@code @sighash} (e.g.
     * {@code "SINGLE|FORKID"}). Validation (security-relevant — a mis-declared
     * mode is an exploit class):
     * <ul>
     *   <li>every name must be a known flag (reject typos like {@code FORKD})</li>
     *   <li>EXACTLY ONE base type (ALL/NONE/SINGLE) — reject zero, and reject
     *       nonsensical combos such as {@code ALL|NONE}. Checked on NAMES, not
     *       the OR-ed numeric value, because {@code ALL|NONE} (0x01|0x02)
     *       collides with the numeric value of SINGLE (0x03).</li>
     *   <li>reject a duplicated flag name.</li>
     *   <li>FORKID is mandatory on BSV (deploy-to-brick otherwise).</li>
     * </ul>
     */
    public static Result parseSighashFlags(String flagsText) {
        String raw = flagsText == null ? "" : flagsText.trim();
        if (raw.isEmpty()) {
            return Result.err("@sighash directive requires at least one flag (e.g. `@sighash ALL|FORKID`)");
        }

        String[] names = raw.split("\\|", -1);
        Set<String> seen = new LinkedHashSet<>();
        java.util.List<String> baseTypes = new java.util.ArrayList<>();
        int value = 0;

        for (String rawName : names) {
            String name = rawName.trim();
            if (name.isEmpty()) {
                return Result.err("@sighash directive has an empty flag in \"" + raw + "\"");
            }
            if (!FLAG_VALUES.containsKey(name)) {
                return Result.err(
                    "@sighash: unknown flag \"" + name
                    + "\" (valid: ALL, NONE, SINGLE, FORKID, ANYONECANPAY)");
            }
            if (seen.contains(name)) {
                return Result.err("@sighash: duplicate flag \"" + name + "\" in \"" + raw + "\"");
            }
            seen.add(name);
            if (BASE_TYPE_NAMES.contains(name)) {
                baseTypes.add(name);
            }
            value |= FLAG_VALUES.get(name);
        }

        if (baseTypes.isEmpty()) {
            return Result.err(
                "@sighash: must specify exactly one base type (ALL, NONE, or SINGLE); got \"" + raw + "\"");
        }
        if (baseTypes.size() > 1) {
            return Result.err(
                "@sighash: cannot combine base types (" + String.join("|", baseTypes)
                + ") — pick exactly one of ALL/NONE/SINGLE");
        }

        // FORKID is mandatory on BSV: the entire OP_PUSH_TX / BIP-143 preimage
        // machinery is FORKID-only, so a FORKID-less flag set deploys a covenant
        // whose derived signature can never verify (deploy-to-brick).
        if ((value & FLAG_VALUES.get("FORKID")) == 0) {
            return Result.err(
                "@sighash: FORKID is mandatory on BSV; write e.g. @sighash "
                + baseTypes.get(0) + "|FORKID (got \"" + raw + "\")");
        }

        return Result.ok(value);
    }

    /**
     * Shared diagnostics (F-039) — identical text in all seven tiers. A marker
     * that is present but not followed by a well-formed flag list, or a second
     * marker on the same method, is a compile error, never a silent fall-back
     * to the default ALL|FORKID mode.
     */
    public static final String SIGHASH_MALFORMED_ERROR =
        "@sighash: malformed directive; expected `@sighash <FLAGS>` where FLAGS is a "
        + "|-separated list of ALL, NONE, SINGLE, FORKID, ANYONECANPAY (e.g. `@sighash SINGLE|FORKID`)";
    public static final String SIGHASH_MULTIPLE_ERROR =
        "@sighash: more than one @sighash directive on this method; declare exactly one";

    /**
     * N-199 (R75): shared diagnostic, identical in all seven tiers, for a
     * {@code @sighash} / {@code @embedAlways} marker inside the contract class
     * body that is not in the leading comments of the member kind that reads it
     * ({@code @sighash} -> a method, {@code @embedAlways} -> a property).
     */
    public static String lostDirectiveMessage(String directive) {
        String target = directive.equals("@embedAlways") ? "property" : "method";
        return directive + " directive is not attached to any " + target
            + " and would be silently ignored; put the comment on its own line directly above the "
            + target + " it annotates (a comment that shares a line with the preceding code belongs to that code)";
    }

    private static final String SIGHASH_MARKER = "@sighash";

    private static boolean isAsciiWordChar(char c) {
        return c == '_' || (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
    }

    /**
     * Extract and parse an {@code @sighash} directive from a method's
     * leading-comment text (all of its leading comments, concatenated). Returns
     * {@code null} only when no {@code @sighash} marker is present, otherwise
     * the parse result (value or error). Mirrors the TS reference.
     *
     * <p>A marker is every occurrence of {@code @sighash}, whatever follows it
     * (N-039, user decision R85): {@code @sighashSINGLE|FORKID} or
     * {@code @sighashType} is a malformed directive, never prose. Once a
     * marker is present (fail-closed, F-039): more than one
     * marker is {@link #SIGHASH_MULTIPLE_ERROR}; the segment after the marker,
     * up to the block-comment close, a newline, CR or the end, must be empty,
     * or start with a space/tab and contain only {@code [A-Za-z0-9_|]}, spaces
     * and tabs, else {@link #SIGHASH_MALFORMED_ERROR}; the flag list itself is
     * then validated by {@link #parseSighashFlags}.
     */
    public static Result extractSighashDirective(String commentText) {
        if (commentText == null) {
            return null;
        }
        java.util.List<Integer> markers = new java.util.ArrayList<>();
        for (int i = commentText.indexOf(SIGHASH_MARKER); i != -1; i = commentText.indexOf(SIGHASH_MARKER, i + 1)) {
            markers.add(i);
        }
        if (markers.isEmpty()) {
            return null;
        }
        if (markers.size() > 1) {
            return Result.err(SIGHASH_MULTIPLE_ERROR);
        }

        String after = commentText.substring(markers.get(0) + SIGHASH_MARKER.length());
        int end = after.length();
        for (int i = 0; i < after.length(); i++) {
            char c = after.charAt(i);
            if (c == '\n' || c == '\r' || (c == '*' && i + 1 < after.length() && after.charAt(i + 1) == '/')) {
                end = i;
                break;
            }
        }
        String seg = after.substring(0, end);
        if (!seg.isEmpty()) {
            boolean ok = seg.charAt(0) == ' ' || seg.charAt(0) == '\t';
            for (int i = 0; ok && i < seg.length(); i++) {
                char c = seg.charAt(i);
                ok = isAsciiWordChar(c) || c == '|' || c == ' ' || c == '\t';
            }
            if (!ok) {
                return Result.err(SIGHASH_MALFORMED_ERROR);
            }
        }
        return parseSighashFlags(seg);
    }

    /**
     * N-093 (R38): resolve a sighash declared with a surface's NATIVE spelling
     * (Solidity {@code sighash(...)}, Move/Rust {@code #[sighash(...)]}, Go
     * {@code //runar:sighash ...}, Python {@code @public(sighash="...")}, Zig
     * {@code runar.Sighash("...")}, Ruby {@code runar_sighash '...'}, Java
     * {@code @Sighash("...")}).
     *
     * <p>{@code specs} holds one entry per spelling found on the method: the
     * flag text, or {@code null} when the spelling's argument was not well
     * formed (a non-identifier token, a non-string argument, ...). Returns
     * {@code null} when there is no spelling, else the numeric type or the
     * diagnostic — the SAME diagnostics the {@code .runar.ts} comment directive
     * produces, checked in the same order: non-public method, then more than
     * one spelling, then malformed, then the flag grammar of
     * {@link #parseSighashFlags}. Mirrors {@code resolveNativeSighash} in the TS
     * reference (sighash-directive.ts); identical in all seven tiers.
     */
    public static Result resolveNativeSighash(String methodName, boolean isPublic, java.util.List<String> specs) {
        if (specs.isEmpty()) {
            return null;
        }
        if (!isPublic) {
            return Result.err("@sighash directive on non-public method '" + methodName
                + "' has no effect — only public methods are spending entry points");
        }
        if (specs.size() > 1) {
            return Result.err("Method '" + methodName + "': " + SIGHASH_MULTIPLE_ERROR);
        }
        String spec = specs.get(0);
        if (spec == null) {
            return Result.err("Method '" + methodName + "': " + SIGHASH_MALFORMED_ERROR);
        }
        Result result = parseSighashFlags(spec);
        if (result.isError()) {
            return Result.err("Method '" + methodName + "': " + result.error());
        }
        return result;
    }

    /**
     * N-093: the Go DSL directive comment {@code //runar:<name> ...}. Only
     * {@code sighash} exists; any other name is refused rather than ignored, so
     * a typo such as {@code //runar:sighsh} cannot silently drop the
     * declaration.
     */
    public static String unknownGoDirectiveMessage(String name) {
        return "unknown Go DSL directive '//runar:" + name + "'; the only directive is //runar:sighash <FLAGS>";
    }

    /** N-093: an attribute on the Move surface other than the two directives. */
    public static String unknownMoveAttributeMessage(String attr) {
        return "unsupported Move attribute #[" + attr
            + "]; the supported attributes are #[embed_always] and #[sighash(<FLAGS>)]";
    }

    /** Human-readable rendering of a sighash value (for diagnostics). */
    public static String describeSighash(int value) {
        java.util.List<String> parts = new java.util.ArrayList<>();
        int base = value & BASE_TYPE_MASK;
        if (base == BASE_ALL) {
            parts.add("ALL");
        } else if (base == BASE_NONE) {
            parts.add("NONE");
        } else if (base == BASE_SINGLE) {
            parts.add("SINGLE");
        } else {
            parts.add("0x" + Integer.toHexString(base));
        }
        if ((value & FLAG_ANYONECANPAY) != 0) {
            parts.add("ANYONECANPAY");
        }
        if ((value & FLAG_FORKID) != 0) {
            parts.add("FORKID");
        }
        return String.join("|", parts);
    }
}
