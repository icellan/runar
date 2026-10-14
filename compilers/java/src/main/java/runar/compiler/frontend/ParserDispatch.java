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

    // Author-facing comment directives implemented only by the TypeScript
    // compiler today: {@code @sighash <FLAGS>} (#123, per-method sighash type)
    // and {@code @embedAlways} (#109, readonly-field DCE opt-out).
    // {@code @embedAlways} is word-boundary anchored (\b) so an identifier like
    // {@code sighashType} does not trip the guard; {@code @sighash} is not
    // (N-244): N-039 made every occurrence of the marker a directive, so a glued
    // {@code @sighashSINGLE|FORKID} is refused too, with the message every tier
    // shares.
    private static final Pattern SIGHASH_DIRECTIVE = Pattern.compile("@sighash");

    /** Non-TS suffix -> surface name in the shared {@code @sighash} diagnostic (N-244). */
    private static final String[][] NON_TS_SURFACES = {
        {".runar.sol", "Solidity"},
        {".runar.move", "Move"},
        {".runar.py", "Python"},
        {".runar.go", "Go DSL"},
        {".runar.rs", "Rust"},
        {".runar.rb", "Ruby"},
        {".runar.zig", "Zig"},
        {".runar.java", "Java"},
    };

    private static String nonTsSurface(String lower) {
        for (String[] s : NON_TS_SURFACES) {
            if (lower.endsWith(s[0])) return s[1];
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

        // Fail-closed guard, NARROWED to the 8 non-TypeScript surface formats
        // (#123/#109 port): the {@code @sighash} (#123, per-method sighash type)
        // and {@code @embedAlways} (#109, readonly-field DCE opt-out) comment
        // directives are honoured ONLY on the {@code .runar.ts} surface, which
        // the {@link TsParser} now parses directly. The other 8 frontends still
        // ignore comments, so they would silently drop these directives and
        // change signing / DCE semantics — keep rejecting them there until (if
        // ever) those tiers port the feature.
        if (source != null && !lower.endsWith(".runar.ts")) {
            String surface = nonTsSurface(lower);
            if (surface != null && SIGHASH_DIRECTIVE.matcher(source).find()) {
                throw new ParseException(
                    "@sighash directive (issue #123) is not supported by the " + surface
                    + " surface parser; write the contract in TypeScript (.runar.ts) where "
                    + "@sighash is honoured");
            }
            if (surface != null && EMBED_ALWAYS_DIRECTIVE.matcher(source).find()) {
                throw new ParseException(
                    "@embedAlways directive (issue #109) is not supported by the " + surface
                    + " surface parser; write the contract in TypeScript (.runar.ts) where "
                    + "@embedAlways is honoured");
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
