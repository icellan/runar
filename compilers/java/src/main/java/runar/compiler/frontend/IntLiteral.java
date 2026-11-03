package runar.compiler.frontend;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * F-026 — integer literals mean what their host language says they mean.
 *
 * <p>A port of the TS reference ({@code packages/runar-compiler/src/passes/int-literal.ts},
 * user decision R15). Every hand-written tokenizer scans a number token over every
 * {@code [0-9A-Za-z_]} character glued to its first digit and validates the whole token
 * against the surface's host-language grammar. The table every tier must reproduce is
 * {@code conformance/negatives/int-literal-cases.json}.
 *
 * <p>A lowercase {@code 0x} on .runar.sol / .runar.move / .runar.rs is a Rúnar ByteString
 * literal, handled by those tokenizers before a number is scanned; on every other surface
 * {@code 0x} is a hexadecimal integer.
 */
public final class IntLiteral {

    private IntLiteral() {}

    /**
     * A validated literal. {@code negOnly} marks a literal valid only as the operand of a
     * unary minus (Java {@code 2147483648}, Rust {@code 128i8}); {@code value} is then the
     * positive magnitude.
     */
    public record Lit(BigInteger value, boolean negOnly) {}

    /** The result of scanning one number token. */
    public record Scan(int end, String value, Lit lit, String raw) {}

    private static final Map<String, String> LANGUAGE = Map.of(
        "ts", "TypeScript", "sol", "Solidity", "move", "Move", "go", "Go", "rs", "Rust",
        "py", "Python", "zig", "Zig", "rb", "Ruby", "java", "Java");

    /** The TS reference's {@code invalidIntegerLiteral()}. */
    public static String invalid(String surface, String text) {
        return "invalid " + LANGUAGE.get(surface) + " integer literal '" + text + "'";
    }

    public static boolean isNumberContinue(char ch) {
        return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || ch == '_';
    }

    /** End (exclusive) of the number token whose first digit is at {@code pos}. */
    public static int scanEnd(String src, int pos) {
        int i = pos + 1;
        while (i < src.length() && isNumberContinue(src.charAt(i))) i++;
        return i;
    }

    private static final Pattern DEC = Pattern.compile("0|[1-9](?:_?[0-9])*");

    private static BigInteger val(String digits, int radix) {
        return new BigInteger(digits.replace("_", ""), radix);
    }

    private static Lit ok(BigInteger v) {
        return new Lit(v, false);
    }

    private static BigInteger pow2(int n) {
        return BigInteger.ONE.shiftLeft(n);
    }

    private static int radixOf(char c) {
        return switch (c) {
            case 'x', 'X' -> 16;
            case 'o', 'O' -> 8;
            case 'b', 'B' -> 2;
            default -> 10;
        };
    }

    private static Lit prefixed(String text, String... patterns) {
        for (String p : patterns) {
            Matcher m = Pattern.compile(p).matcher(text);
            if (m.matches()) return ok(val(m.group(1), radixOf(text.charAt(1))));
        }
        return null;
    }

    private static Lit ts(String text) {
        String body = text.endsWith("n") ? text.substring(0, text.length() - 1) : text;
        if (DEC.matcher(body).matches()) return ok(val(body, 10));
        return prefixed(body, "0[xX]([0-9a-fA-F](?:_?[0-9a-fA-F])*)", "0[oO]([0-7](?:_?[0-7])*)", "0[bB]([01](?:_?[01])*)");
    }

    private static final Map<String, Integer> MOVE_BITS = Map.of(
        "u8", 8, "u16", 16, "u32", 32, "u64", 64, "u128", 128, "u256", 256);

    private static Lit move(String text) {
        Matcher m = Pattern.compile("([0-9][0-9_]*)(u8|u16|u32|u64|u128|u256)?").matcher(text);
        if (!m.matches()) return null;
        BigInteger v = val(m.group(1), 10);
        int bits = MOVE_BITS.get(m.group(2) == null ? "u256" : m.group(2));
        return v.compareTo(pow2(bits)) < 0 ? ok(v) : null;
    }

    private static Lit go(String text) {
        if (DEC.matcher(text).matches()) return ok(val(text, 10));
        Matcher m = Pattern.compile("0((?:_?[0-7])+)").matcher(text);
        if (m.matches()) return ok(val(m.group(1), 8));
        return prefixed(text, "0[xX]((?:_?[0-9a-fA-F])+)", "0[oO]((?:_?[0-7])+)", "0[bB]((?:_?[01])+)");
    }

    private static final Pattern RUST = Pattern.compile(
        "(?:0x([0-9a-fA-F_]*)|0o([0-7_]*)|0b([01_]*)|([0-9][0-9_]*))"
            + "(i8|i16|i32|i64|i128|isize|u8|u16|u32|u64|u128|usize)?");

    private static Lit rust(String text) {
        Matcher m = RUST.matcher(text);
        if (!m.matches()) return null;
        String digits;
        int radix;
        if (m.group(1) != null) { digits = m.group(1); radix = 16; }
        else if (m.group(2) != null) { digits = m.group(2); radix = 8; }
        else if (m.group(3) != null) { digits = m.group(3); radix = 2; }
        else { digits = m.group(4); radix = 10; }
        if (!digits.matches(".*[0-9a-fA-F].*")) return null;
        BigInteger v = val(digits, radix);
        String suffix = m.group(5);
        // Unsuffixed values are unbounded: rustc stops at u128::MAX, but Rúnar's
        // Int is a bigint and the corpus spells 256-bit constants this way.
        if (suffix == null) return ok(v);
        int bits = switch (suffix) {
            case "i8", "u8" -> 8;
            case "i16", "u16" -> 16;
            case "i32", "u32" -> 32;
            case "i128", "u128" -> 128;
            default -> 64; // i64, u64, isize, usize
        };
        if (suffix.startsWith("u")) return v.compareTo(pow2(bits)) < 0 ? ok(v) : null;
        BigInteger lo = pow2(bits - 1);
        int c = v.compareTo(lo);
        if (c < 0) return ok(v);
        return c == 0 ? new Lit(v, true) : null;
    }

    private static Lit py(String text) {
        if (text.matches("[1-9](?:_?[0-9])*|0(?:_?0)*")) return ok(val(text, 10));
        return prefixed(text, "0[xX]((?:_?[0-9a-fA-F])+)", "0[oO]((?:_?[0-7])+)", "0[bB]((?:_?[01])+)");
    }

    private static Lit zig(String text) {
        if (DEC.matcher(text).matches()) return ok(val(text, 10));
        return prefixed(text, "0x([0-9a-fA-F](?:_?[0-9a-fA-F])*)", "0o([0-7](?:_?[0-7])*)", "0b([01](?:_?[01])*)");
    }

    private static Lit rb(String text) {
        if (DEC.matcher(text).matches()) return ok(val(text, 10));
        Matcher m = Pattern.compile("0(_?[0-7](?:_?[0-7])*)").matcher(text);
        if (m.matches()) return ok(val(m.group(1), 8));
        return prefixed(text, "0[dD]([0-9](?:_?[0-9])*)", "0[xX]([0-9a-fA-F](?:_?[0-9a-fA-F])*)",
            "0[oO]([0-7](?:_?[0-7])*)", "0[bB]([01](?:_?[01])*)");
    }

    private static Lit java(String text) {
        boolean isLong = text.endsWith("L") || text.endsWith("l");
        String body = isLong ? text.substring(0, text.length() - 1) : text;
        int bits = isLong ? 64 : 32;
        if (body.matches("0|[1-9](?:[0-9_]*[0-9])?")) {
            BigInteger v = val(body, 10);
            int c = v.compareTo(pow2(bits - 1));
            if (c < 0) return ok(v);
            return c == 0 ? new Lit(v, true) : null;
        }
        BigInteger v = null;
        Matcher m;
        if ((m = Pattern.compile("0([0-7_]*[0-7])").matcher(body)).matches()) v = val(m.group(1), 8);
        if ((m = Pattern.compile("0[xX]([0-9a-fA-F](?:[0-9a-fA-F_]*[0-9a-fA-F])?)").matcher(body)).matches()) v = val(m.group(1), 16);
        if ((m = Pattern.compile("0[bB]([01](?:[01_]*[01])?)").matcher(body)).matches()) v = val(m.group(1), 2);
        if (v == null || v.compareTo(pow2(bits)) >= 0) return null;
        return ok(v.compareTo(pow2(bits - 1)) >= 0 ? v.subtract(pow2(bits)) : v);
    }

    /**
     * The value of the integer literal {@code text} (the whole number token) on
     * {@code surface}, or null when the host language rejects it.
     */
    public static Lit parse(String surface, String text) {
        return switch (surface) {
            case "ts" -> ts(text);
            case "sol" -> DEC.matcher(text).matches() ? ok(val(text, 10)) : null;
            case "move" -> move(text);
            case "go" -> go(text);
            case "rs" -> rust(text);
            case "py" -> py(text);
            case "zig" -> zig(text);
            case "rb" -> rb(text);
            case "java" -> java(text);
            default -> null;
        };
    }

    /**
     * Scan the number token at {@code pos}. A refused literal is reported to {@code lex}
     * with the shared diagnostic and reads as "0".
     */
    public static Scan lex(String surface, String src, int pos, List<String> lex, String file, int line, int col) {
        int end = scanEnd(src, pos);
        String text = src.substring(pos, end);
        Lit lit = parse(surface, text);
        if (lit == null) {
            if (lex != null) lex.add(LexDiag.at(file, line, col, invalid(surface, text)));
            return new Scan(end, "0", null, text);
        }
        return new Scan(end, lit.value().toString(), lit, text);
    }
}
