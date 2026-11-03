package runar.compiler.frontend;

import java.util.regex.Pattern;
import runar.compiler.ir.ast.ContractNode;

/**
 * Routes a Rúnar source file to the correct front-end parser based on its
 * {@code .runar.<lang>} file extension. Mirrors the dispatch logic found in
 * the other six compilers (TypeScript {@code 01-parse.ts}, Go {@code
 * frontend.ParseSource}, Rust {@code parser::parse_source}, Python {@code
 * parse_source}, Zig {@code parseSource}, Ruby {@code parse_source}).
 *
 * <p>All Rúnar surface formats produce identical {@link ContractNode} ASTs for
 * the same logical contract, so once dispatch lands the rest of the Java
 * pipeline is format-agnostic.
 */
public final class ParserDispatch {
    private ParserDispatch() {}

    // The author-facing comment directives {@code @sighash <FLAGS>} (#123,
    // per-method sighash type) and {@code @embedAlways} (#109, readonly-field
    // DCE opt-out) are read from COMMENTS only on the TypeScript surface. The
    // eight non-TS surfaces spell both directives natively instead (N-093, user
    // decision R38: a modifier mirroring each surface's readonly idiom — see
    // NON_TS_SURFACES), and their parsers drop comments, so a COMMENT directive
    // in one of those sources would be silently ignored and change signing /
    // DCE semantics. Fail closed on those formats rather than miscompile, and
    // name the native spelling to use. None of the native spellings contains
    // either marker, so this guard never trips on them.
    // {@code @embedAlways} is word-boundary anchored (\b) so an identifier like
    // {@code sighashType} does not trip the guard; {@code @sighash} is not
    // (N-244): N-039 made every occurrence of the marker a directive, so a glued
    // {@code @sighashSINGLE|FORKID} is refused too, with the message every tier
    // shares.
    private static final Pattern SIGHASH_DIRECTIVE = Pattern.compile("@sighash");

    /**
     * Non-TS suffix -> surface name, format doc, and the native spelling of
     * each directive on that surface (N-093), for the shared comment-guard
     * diagnostic. Mirrors NON_TS_SURFACES in the TS reference (01-parse.ts).
     */
    private static final String[][] NON_TS_SURFACES = {
        {".runar.sol", "Solidity", "solidity", "the function modifier sighash(<FLAGS>)", "the property modifier embedAlways"},
        {".runar.move", "Move", "move", "the attribute #[sighash(<FLAGS>)]", "the attribute #[embed_always]"},
        {".runar.py", "Python", "python", "@public(sighash=\"<FLAGS>\")", "the wrapper type EmbedAlways[T]"},
        {".runar.go", "Go DSL", "go", "the directive //runar:sighash <FLAGS>", "the struct tag option runar:\"readonly,embedAlways\""},
        {".runar.rs", "Rust", "rust", "the attribute #[sighash(<FLAGS>)]", "the attribute #[embed_always]"},
        {".runar.rb", "Ruby", "ruby", "runar_sighash '<FLAGS>'", "the prop option embed_always: true"},
        {".runar.zig", "Zig", "zig", "the return type runar.Sighash(\"<FLAGS>\")", "the type function runar.EmbedAlways(T)"},
        {".runar.java", "Java", "java", "the annotation @Sighash(\"<FLAGS>\")", "the annotation @EmbedAlways"},
    };

    private static String[] nonTsSurface(String lower) {
        for (String[] s : NON_TS_SURFACES) {
            if (lower.endsWith(s[0])) return s;
        }
        return null;
    }
    private static final Pattern EMBED_ALWAYS_DIRECTIVE = Pattern.compile("@embedAlways\\b");

    /**
     * Parse {@code source} into a {@link ContractNode}, dispatching by the
     * format suffix in {@code filename}. Recognised suffixes:
     * {@code .runar.{ts,sol,move,py,go,rs,zig,rb,java}}.
     */
    public static ContractNode parse(String source, String filename) throws ParseException {
        // N-115: `10 > i` is `i < 10`; every later pass sees the canonical form.
        return LoopCondition.normalizeContract(parseDispatch(source, filename));
    }

    private static ContractNode parseDispatch(String source, String filename) throws ParseException {
        // DoS-bound size guard. Reject oversized source BEFORE any
        // format-specific parser touches the input. Raises
        // InputLimits.SourceSizeExceededException (a ParseException
        // subclass) on rejection. BUG-008 follow-up.
        InputLimits.assertSourceBytesUnderLimit(source);

        String lower = filename == null ? "" : filename.toLowerCase();

        // Fail-closed guard on the 8 non-TypeScript surface formats: a
        // {@code @sighash} (#123) / {@code @embedAlways} (#109) COMMENT
        // directive would be silently dropped by those parsers (they ignore
        // comments), so refuse it and name the surface's native spelling
        // (N-093). The {@code .runar.ts} surface reads the comment form.
        if (source != null && !lower.endsWith(".runar.ts")) {
            String[] surface = nonTsSurface(lower);
            if (surface != null && SIGHASH_DIRECTIVE.matcher(source).find()) {
                throw new ParseException(
                    "@sighash directive (issue #123) is not supported as a comment by the " + surface[1]
                    + " surface parser; write it as " + surface[3] + " (see docs/formats/" + surface[2] + ".md)");
            }
            if (surface != null && EMBED_ALWAYS_DIRECTIVE.matcher(source).find()) {
                throw new ParseException(
                    "@embedAlways directive (issue #109) is not supported as a comment by the " + surface[1]
                    + " surface parser; write it as " + surface[4] + " (see docs/formats/" + surface[2] + ".md)");
            }
        }

        try {
            if (lower.endsWith(".runar.java")) {
                return JavaParser.parse(source, filename);
            }
            if (lower.endsWith(".runar.ts")) {
                return TsParser.parse(source, filename);
            }
            if (lower.endsWith(".runar.sol")) {
                return SolParser.parse(source, filename);
            }
            if (lower.endsWith(".runar.move")) {
                return MoveParser.parse(source, filename);
            }
            if (lower.endsWith(".runar.py")) {
                return PyParser.parse(source, filename);
            }
            if (lower.endsWith(".runar.go")) {
                return GoParser.parse(source, filename);
            }
            if (lower.endsWith(".runar.rs")) {
                return RustParser.parse(source, filename);
            }
            if (lower.endsWith(".runar.zig")) {
                return ZigParser.parse(source, filename);
            }
            if (lower.endsWith(".runar.rb")) {
                return RbParser.parse(source, filename);
            }
        } catch (JavaParser.ParseException e) {
            throw new ParseException(e.getMessage(), e);
        } catch (TsParser.ParseException e) {
            throw new ParseException(e.getMessage(), e);
        } catch (SolParser.ParseException e) {
            throw new ParseException(e.getMessage(), e);
        } catch (MoveParser.ParseException e) {
            throw new ParseException(e.getMessage(), e);
        } catch (PyParser.ParseException e) {
            throw new ParseException(e.getMessage(), e);
        } catch (GoParser.ParseException e) {
            throw new ParseException(e.getMessage(), e);
        } catch (RustParser.ParseException e) {
            throw new ParseException(e.getMessage(), e);
        } catch (ZigParser.ParseException e) {
            throw new ParseException(e.getMessage(), e);
        } catch (RbParser.ParseException e) {
            throw new ParseException(e.getMessage(), e);
        } catch (RuntimeException e) {
            throw new ParseException(e.getMessage(), e);
        }
        throw new ParseException(
            "ParserDispatch: unrecognised file extension for " + filename
            + " (expected .runar.{ts,sol,move,py,go,rs,zig,rb,java})");
    }

    /** Unified parse-error type that adapts the per-parser exceptions.
     *  Non-final so {@link InputLimits.SourceSizeExceededException} can
     *  extend it for typed DoS-bound rejection (BUG-008 follow-up). */
    public static class ParseException extends Exception {
        public ParseException(String message) {
            super(message);
        }
        public ParseException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
